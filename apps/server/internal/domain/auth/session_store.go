package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
)

// SessionStore keeps ephemeral auth state and one-time tokens in Redis.
type SessionStore interface {
	CreateSession(ctx context.Context, sess Session, ttl time.Duration) error
	GetSession(ctx context.Context, sessionID uuid.UUID) (Session, error)
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error
	DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error
	DeleteAllUserSessionsExcept(ctx context.Context, userID, keepSessionID uuid.UUID) error
	TouchSession(ctx context.Context, sessionID uuid.UUID, expiresAt, lastActivity time.Time, ttl time.Duration) error
	RevokeSession(ctx context.Context, sessionID uuid.UUID, revokedAt time.Time) error

	StoreMagicToken(ctx context.Context, tokenHash string, userID uuid.UUID, ttl time.Duration) error
	ConsumeMagicToken(ctx context.Context, tokenHash string) (uuid.UUID, error)
	StoreEmailVerificationToken(ctx context.Context, tokenHash string, userID uuid.UUID, ttl time.Duration) error
	ConsumeEmailVerificationToken(ctx context.Context, tokenHash string) (uuid.UUID, error)
	StorePasswordResetToken(ctx context.Context, tokenHash string, userID uuid.UUID, ttl time.Duration) error
	ConsumePasswordResetToken(ctx context.Context, tokenHash string) (uuid.UUID, error)
}

type RedisSessionStore struct {
	cli *goredis.Client
}

func NewSessionStore(cli *goredis.Client) *RedisSessionStore {
	return &RedisSessionStore{cli: cli}
}

type redisSessionPayload struct {
	ID                string  `json:"id"`
	UserID            string  `json:"user_id"`
	OrgID             *string `json:"org_id,omitempty"`
	ActiveVenueID     *string `json:"active_venue_id,omitempty"`
	Role              string  `json:"role"`
	Plan              string  `json:"plan"`
	TokenHash         string  `json:"token_hash"`
	IPAddress         string  `json:"ip_address"`
	UserAgent         string  `json:"user_agent"`
	MFAVerified       bool    `json:"mfa_verified"`
	ExpiresAt         int64   `json:"expires_at"`
	AbsoluteExpiresAt int64   `json:"absolute_expires_at"`
	LastActivityAt    int64   `json:"last_activity_at"`
	RevokedAt         *int64  `json:"revoked_at,omitempty"`
	CreatedAt         int64   `json:"created_at"`
}
