package service

import (
	"authorization_authentication/config"
	"authorization_authentication/internal/model"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTService struct {
	privateKey []byte
	publicKey  []byte
}

func NewJWTService(cfg *config.Config) (*JWTService, error) {
	privateKey, err := os.ReadFile(cfg.JWTPrivate)
	if err != nil {
		return nil, err
	}

	publicKey, err := os.ReadFile(cfg.JWTPublic)
	if err != nil {
		return nil, err
	}

	return &JWTService{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func (s *JWTService) GenerateToken(userID string) (string, int64, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(s.privateKey)
	if err != nil {
		return "", 0, err
	}

	now := time.Now()
	expiresAt := now.Add(15 * time.Minute)
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": expiresAt.Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", 0, err
	}

	return tokenString, expiresAt.Unix(), nil
}

func (s *JWTService) ValidateToken(tokenString string) (*jwt.MapClaims, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(s.publicKey)
	if err != nil {
		return nil, err
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return nil, model.ErrInvalidToken
	}

	if !token.Valid {
		return nil, model.ErrInvalidToken
	}

	return &claims, nil
}

func (s *JWTService) ValidateAndGetUserID(tokenString string) (string, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	userID, ok := (*claims)["sub"].(string)
	if !ok {
		return "", model.ErrInvalidTokenClaims
	}

	return userID, nil
}
