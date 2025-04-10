package repository

import (
	"authorization_authentication/internal/model"
	"context"
	"database/sql"
	"errors"
	"time"
)

type SessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) CreateSession(ctx context.Context, session *model.Session) error {
	query := `
		INSERT INTO sessions (
			id, user_id, refresh_token, expires_at, 
			user_agent, ip, is_revoked, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (refresh_token) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, query,
		session.ID,
		session.UserID,
		session.RefreshToken,
		session.ExpiresAt.UTC(),
		session.UserAgent,
		session.IP,
		session.IsRevoked,
		session.CreatedAt.UTC(),
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *SessionRepository) GetSessionByToken(ctx context.Context, refreshTokenHash string) (*model.Session, error) {
	query := `
		SELECT id, user_id, refresh_token, expires_at, 
		       created_at, user_agent, ip, is_revoked
		FROM sessions
		WHERE refresh_token = $1 AND is_revoked = false
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, refreshTokenHash)

	var session model.Session
	err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.RefreshToken,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.UserAgent,
		&session.IP,
		&session.IsRevoked,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, model.ErrSessionNotFound
		}
		return nil, err
	}
	return &session, nil
}

func (r *SessionRepository) RevokeSession(ctx context.Context, sessionID string) error {
	query := `
		UPDATE sessions 
		SET is_revoked = true 
		WHERE id = $1 AND is_revoked = false
		RETURNING id
	`
	var id string
	err := r.db.QueryRowContext(ctx, query, sessionID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ErrSessionNotFound
		}
		return err
	}
	return nil
}

func (r *SessionRepository) RevokeAllUserSessions(ctx context.Context, userID string) error {
	query := `
		UPDATE sessions 
		SET is_revoked = true 
		WHERE user_id = $1 AND is_revoked = false
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *SessionRepository) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM sessions 
		WHERE expires_at < $1
		RETURNING COUNT(*)
	`
	var count int64
	err := r.db.QueryRowContext(ctx, query, time.Now().UTC()).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (r *SessionRepository) GetUserActiveSessions(ctx context.Context, userID string) ([]*model.Session, error) {
	query := `
		SELECT id, user_id, refresh_token, expires_at, 
		       created_at, user_agent, ip, is_revoked
		FROM sessions
		WHERE user_id = $1 AND is_revoked = false AND expires_at > NOW()
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*model.Session
	for rows.Next() {
		var session model.Session
		err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.RefreshToken,
			&session.ExpiresAt,
			&session.CreatedAt,
			&session.UserAgent,
			&session.IP,
			&session.IsRevoked,
		)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, &session)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return sessions, nil
}
