package model

import (
	"authorization_authentication/internal/util"
	"time"
)

type Session struct {
	ID           string    `json:"id" db:"id"`
	UserID       string    `json:"user_id" db:"user_id"`
	RefreshToken string    `json:"refresh_token" db:"refresh_token"` //TODO: bcrypt
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UserAgent    string    `json:"user_agent" db:"user_agent"`
	IP           string    `json:"ip" db:"ip"`
	IsRevoked    bool      `json:"is_revoked" db:"is_revoked"`
}

// SetIP безопасно устанавливает IP с валидацией
func (s *Session) SetIP(rawIP string) error {
	normalizedIP, err := util.NormalizeIP(rawIP)
	if err != nil {
		return err
	}
	s.IP = normalizedIP
	return nil
}

// SetIPWithPort сохраняет IP с портом
func (s *Session) SetIPWithPort(rawIP string) error {
	normalizedIP, err := util.NormalizeIPWithPort(rawIP)
	if err != nil {
		return err
	}
	s.IP = normalizedIP
	return nil
}
