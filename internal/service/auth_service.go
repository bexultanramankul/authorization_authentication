package service

import (
	"authorization_authentication/internal/model"
	"authorization_authentication/internal/repository"
	"authorization_authentication/internal/util"
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AuthService struct {
	userRepo    repository.UserRepository
	sessionRepo repository.SessionRepository
	jwtService  *JWTService
}

func NewAuthService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	jwtService *JWTService,
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		jwtService:  jwtService,
	}
}

func (s *AuthService) Register(ctx context.Context, email, password string) (*model.User, error) {
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

	user := &model.User{
		ID:        uuid.NewString(),
		Email:     email,
		Password:  hashedPassword,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if err := s.userRepo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *AuthService) Login(ctx context.Context, email, password, userAgent, ip string) (*model.AuthTokens, error) {
	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, model.ErrUserNotFound
	}

	if !util.CheckPasswordHash(password, user.Password) {
		return nil, model.ErrInvalidCredentials
	}

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
