package service

import (
	"authorization_authentication/internal/model"
	"authorization_authentication/internal/repository"
	"authorization_authentication/internal/util"
	"context"
	"github.com/redis/go-redis/v9"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/twilio/twilio-go"
	verify "github.com/twilio/twilio-go/rest/verify/v2"
)

type AuthService struct {
	userRepo     repository.UserRepository
	sessionRepo  repository.SessionRepository
	jwtService   *JWTService
	redisClient  *redis.Client
	twilioClient *twilio.RestClient
	serviceSID   string
}

func NewAuthService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	jwtService *JWTService,
	redisClient *redis.Client,
	twilioClient *twilio.RestClient,
	serviceSID string,
) *AuthService {
	return &AuthService{
		userRepo:     userRepo,
		sessionRepo:  sessionRepo,
		jwtService:   jwtService,
		redisClient:  redisClient,
		twilioClient: twilioClient,
		serviceSID:   serviceSID,
	}
}

const (
	maxLoginAttempts = 5
	blockDuration    = 5 * time.Minute
	ipBlockDuration  = 30 * time.Minute // Более долгая блокировка по IP
	maxIPAttempts    = 15               // Больше попыток для IP
	cleanupInterval  = 1 * time.Hour    // Интервал очистки старых записей
)

func (s *AuthService) Register(ctx context.Context, email, password, phone string) (*model.User, error) {
	existingUser, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, model.ErrUserAlreadyExists
	}

	hashedPassword, err := util.HashPassword(password)
	if err != nil {
		return nil, err
	}

	if phone == "" {
		return nil, model.ErrPhoneRequired
	}

	// Создаем пользователя (пока не верифицирован)
	user := &model.User{
		ID:        uuid.NewString(),
		Email:     email,
		Phone:     phone,
		Verified:  false, // По умолчанию не верифицирован
		Password:  hashedPassword,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	// Отправляем SMS с кодом верификации
	if err := s.sendVerificationCode(user.Phone); err != nil {
		return nil, err
	}

	// Сохраняем пользователя
	if err := s.userRepo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *AuthService) sendVerificationCode(phone string) error {
	params := &verify.CreateVerificationParams{}
	params.SetTo(phone)
	params.SetChannel("sms")

	_, err := s.twilioClient.VerifyV2.CreateVerification(s.serviceSID, params)
	return err
}

func (s *AuthService) VerifyPhone(ctx context.Context, phone, code string) error {
	params := &verify.CreateVerificationCheckParams{}
	params.SetTo(phone)
	params.SetCode(code)

	resp, err := s.twilioClient.VerifyV2.CreateVerificationCheck(s.serviceSID, params)
	if err != nil {
		return err
	}

	if *resp.Status != "approved" {
		return model.ErrVerificationFailed
	}

	// Обновляем статус верификации пользователя
	return s.userRepo.UpdateVerificationStatus(ctx, phone, true)
}

func (s *AuthService) Login(ctx context.Context, email, password, userAgent, ip string) (*model.AuthTokens, error) {
	// Нормализация IP (если используется прокси, нужно учитывать X-Forwarded-For)
	normalizedIP, err := util.NormalizeIP(ip)
	if err != nil {
		return nil, err
	}

	// Проверка блокировки по IP
	if err := s.checkIPAttempts(ctx, normalizedIP); err != nil {
		return nil, err
	}

	// Проверка блокировки по email
	if err := s.checkLoginAttempts(ctx, email); err != nil {
		return nil, err
	}

	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		s.incrementIPAttempts(ctx, normalizedIP) // Увеличиваем счетчик для IP при любой ошибке
		return nil, err
	}

	if user == nil {
		s.incrementLoginAttempts(ctx, email)
		s.incrementIPAttempts(ctx, normalizedIP)
		return nil, model.ErrUserNotFound
	}

	if !util.CheckPasswordHash(password, user.Password) {
		s.incrementLoginAttempts(ctx, email)
		s.incrementIPAttempts(ctx, normalizedIP)
		return nil, model.ErrInvalidCredentials
	}

	// Сброс счетчиков при успешном входе
	s.resetLoginAttempts(ctx, email)
	s.resetIPAttempts(ctx, normalizedIP)

	accessToken, expiresAtUnix, err := s.jwtService.GenerateToken(user.ID)
	if err != nil {
		return nil, err
	}

	refreshToken := uuid.NewString()
	refreshExpiresAt := time.Now().UTC().Add(7 * 24 * time.Hour)

	session := &model.Session{
		ID:           uuid.NewString(),
		UserID:       user.ID,
		RefreshToken: refreshToken,
		ExpiresAt:    refreshExpiresAt,
		UserAgent:    userAgent,
		IP:           ip,
		CreatedAt:    time.Now().UTC(),
	}

	if err := s.sessionRepo.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	return &model.AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(time.Unix(expiresAtUnix, 0).Sub(time.Now()).Seconds()),
	}, nil
}

func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*model.AuthTokens, error) {
	session, err := s.sessionRepo.GetSessionByToken(ctx, refreshToken)
	if err != nil {
		return nil, model.ErrInvalidSession
	}

	if session.IsRevoked || session.ExpiresAt.Before(time.Now().UTC()) {
		return nil, model.ErrSessionExpired
	}

	if err := s.sessionRepo.RevokeSession(ctx, session.ID); err != nil {
		return nil, err
	}

	accessToken, expiresAtUnix, err := s.jwtService.GenerateToken(session.UserID)
	if err != nil {
		return nil, err
	}

	newRefreshToken := uuid.NewString()
	newExpiresAt := time.Now().UTC().Add(7 * 24 * time.Hour)

	newSession := &model.Session{
		ID:           uuid.NewString(),
		UserID:       session.UserID,
		RefreshToken: newRefreshToken,
		ExpiresAt:    newExpiresAt,
		CreatedAt:    time.Now().UTC(),
	}

	if err := s.sessionRepo.CreateSession(ctx, newSession); err != nil {
		return nil, err
	}

	return &model.AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int(time.Unix(expiresAtUnix, 0).Sub(time.Now()).Seconds()),
	}, nil
}

func (s *AuthService) VerifyToken(token string) (*jwt.MapClaims, error) {
	return s.jwtService.ValidateToken(token)
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	session, err := s.sessionRepo.GetSessionByToken(ctx, refreshToken)
	if err != nil {
		return model.ErrInvalidSession
	}

	return s.sessionRepo.RevokeSession(ctx, session.ID)
}

func (s *AuthService) checkLoginAttempts(ctx context.Context, email string) error {
	key := "login_attempts:" + email

	// Получаем текущее количество попыток
	attempts, err := s.redisClient.Get(ctx, key).Int()
	if err != nil && err != redis.Nil {
		return err
	}

	if attempts >= maxLoginAttempts {
		return model.ErrTooManyAttempts
	}

	return nil
}

func (s *AuthService) incrementLoginAttempts(ctx context.Context, email string) error {
	key := "login_attempts:" + email

	// Увеличиваем счетчик попыток
	_, err := s.redisClient.Incr(ctx, key).Result()
	if err != nil {
		return err
	}

	// Устанавливаем TTL для ключа
	if _, err := s.redisClient.Expire(ctx, key, blockDuration).Result(); err != nil {
		return err
	}

	return nil
}

func (s *AuthService) resetLoginAttempts(ctx context.Context, email string) error {
	key := "login_attempts:" + email
	return s.redisClient.Del(ctx, key).Err()
}

// Методы для работы с блокировкой по IP
func (s *AuthService) checkIPAttempts(ctx context.Context, ip string) error {
	key := "ip_attempts:" + ip

	attempts, err := s.redisClient.Get(ctx, key).Int()
	if err != nil && err != redis.Nil {
		return err
	}

	if attempts >= maxIPAttempts {
		return model.ErrIPBlocked
	}

	return nil
}

func (s *AuthService) incrementIPAttempts(ctx context.Context, ip string) error {
	key := "ip_attempts:" + ip

	_, err := s.redisClient.Incr(ctx, key).Result()
	if err != nil {
		return err
	}

	if _, err := s.redisClient.Expire(ctx, key, ipBlockDuration).Result(); err != nil {
		return err
	}

	return nil
}

func (s *AuthService) resetIPAttempts(ctx context.Context, ip string) error {
	key := "ip_attempts:" + ip
	return s.redisClient.Del(ctx, key).Err()
}

// Фоновая очистка старых записей
func (s *AuthService) StartCleanupRoutine(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.cleanupOldAttempts(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *AuthService) cleanupOldAttempts(ctx context.Context) {
	// В реальной реализации нужно использовать SCAN для больших БД
	// Здесь упрощенный вариант для демонстрации
	keys, _ := s.redisClient.Keys(ctx, "*attempts*").Result()
	for _, key := range keys {
		ttl, err := s.redisClient.TTL(ctx, key).Result()
		if err == nil && ttl < 0 {
			s.redisClient.Del(ctx, key)
		}
	}
}
