package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository persists durable auth data in PostgreSQL.
type Repository interface {
	CreateUser(ctx context.Context, email, displayName, passwordHash string) (User, error)
	CreateOAuthUser(ctx context.Context, email, displayName string) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (User, error)
	GetPrimaryMembership(ctx context.Context, userID uuid.UUID) (Membership, error)
	MarkEmailVerified(ctx context.Context, userID uuid.UUID) error
	UpsertOAuthAccount(ctx context.Context, userID uuid.UUID, account OAuthAccount) error
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
	IncrementFailedLogin(ctx context.Context, userID uuid.UUID, maxAttempts int, lockFor time.Duration) error
	ResetFailedLogin(ctx context.Context, userID uuid.UUID) error

	CreateRefreshToken(ctx context.Context, token RefreshToken, ip, ua string) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (RefreshToken, error)
	RotateRefreshToken(ctx context.Context, oldTokenID uuid.UUID, newToken RefreshToken, ip, ua string) error
	RevokeRefreshTokenByID(ctx context.Context, tokenID uuid.UUID) error
	RevokeRefreshFamily(ctx context.Context, familyID uuid.UUID) error
	RevokeAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error
	RevokeAllUserRefreshTokensExceptSession(ctx context.Context, userID, keepSessionID uuid.UUID) error
}

type SQLRepository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *SQLRepository {
	return &SQLRepository{pool: pool}
}

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(
		&u.ID,
		&u.Email,
		&u.DisplayName,
		&u.PasswordHash,
		&u.EmailVerified,
		&u.IsActive,
		&u.IsSuspended,
		&u.FailedLoginAttempts,
		&u.LockedUntil,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return User{}, pgx.ErrNoRows
		}
		return User{}, fmt.Errorf("scan user: %w", err)
	}
	return u, nil
}

func nullableIP(ip string) any {
	if ip == "" {
		return nil
	}
	return ip
}

func nullableText(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func formatInterval(d time.Duration) string {
	sec := int64(d.Seconds())
	if sec <= 0 {
		sec = 60
	}
	return fmt.Sprintf("%d seconds", sec)
}
