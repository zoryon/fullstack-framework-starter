package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
)

func (s *RedisSessionStore) StoreMagicToken(ctx context.Context, tokenHash string, userID uuid.UUID, ttl time.Duration) error {
	return s.cli.Set(ctx, "magic:"+tokenHash, userID.String(), ttl).Err()
}

func (s *RedisSessionStore) ConsumeMagicToken(ctx context.Context, tokenHash string) (uuid.UUID, error) {
	return s.consumeUUIDToken(ctx, "magic:"+tokenHash)
}

func (s *RedisSessionStore) StoreEmailVerificationToken(ctx context.Context, tokenHash string, userID uuid.UUID, ttl time.Duration) error {
	return s.cli.Set(ctx, "verify:"+tokenHash, userID.String(), ttl).Err()
}

func (s *RedisSessionStore) ConsumeEmailVerificationToken(ctx context.Context, tokenHash string) (uuid.UUID, error) {
	return s.consumeUUIDToken(ctx, "verify:"+tokenHash)
}

func (s *RedisSessionStore) StorePasswordResetToken(ctx context.Context, tokenHash string, userID uuid.UUID, ttl time.Duration) error {
	return s.cli.Set(ctx, "reset:"+tokenHash, userID.String(), ttl).Err()
}

func (s *RedisSessionStore) ConsumePasswordResetToken(ctx context.Context, tokenHash string) (uuid.UUID, error) {
	return s.consumeUUIDToken(ctx, "reset:"+tokenHash)
}

func (s *RedisSessionStore) consumeUUIDToken(ctx context.Context, key string) (uuid.UUID, error) {
	val, err := s.cli.GetDel(ctx, key).Result()
	if err != nil {
		if err == goredis.Nil {
			return uuid.Nil, ErrInvalidToken
		}
		return uuid.Nil, fmt.Errorf("consume token: %w", err)
	}

	id, err := uuid.Parse(val)
	if err != nil {
		return uuid.Nil, fmt.Errorf("parse token user id: %w", err)
	}
	return id, nil
}
