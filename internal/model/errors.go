package model

import "errors"

var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrInvalidTokenClaims = errors.New("invalid token claims")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrSessionNotFound    = errors.New("session not found")
	ErrInvalidSession     = errors.New("invalid session")
	ErrSessionExpired     = errors.New("session expired or revoked")
	ErrTooManyAttempts    = errors.New("too many login attempts, please try again later")
	ErrIPBlocked          = errors.New("your IP address has been temporarily blocked")
	ErrPhoneRequired      = errors.New("phone number is required")
	ErrNotVerified        = errors.New("account not verified")
	ErrVerificationFailed = errors.New("verification failed")
)
