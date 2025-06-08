package repository

import (
	"authorization_authentication/internal/model"
	"context"
	"database/sql"
	"errors"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CreateUser(ctx context.Context, user *model.User) error {
	query := `INSERT INTO users 
		(id, email, phone, verified, password_hash, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.ExecContext(ctx, query,
		user.ID, user.Email, user.Phone, user.Verified,
		user.Password, user.CreatedAt, user.UpdatedAt)
	return err
}

func (r *UserRepository) UpdateVerificationStatus(ctx context.Context, phone string, verified bool) error {
	query := `UPDATE users SET verified = $1, updated_at = NOW() WHERE phone = $2`
	_, err := r.db.ExecContext(ctx, query, verified, phone)
	return err
}

func (r *UserRepository) GetUserByPhone(ctx context.Context, phone string) (*model.User, error) {
	query := `SELECT id, email, phone, verified FROM users WHERE phone = $1`
	row := r.db.QueryRowContext(ctx, query, phone)

	user := &model.User{}
	err := row.Scan(&user.ID, &user.Email, &user.Phone, &user.Verified)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `SELECT id, email, password_hash FROM users WHERE email = $1`
	row := r.db.QueryRowContext(ctx, query, email)

	user := &model.User{}
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}
