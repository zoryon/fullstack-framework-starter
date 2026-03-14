package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
)

func (s *RedisSessionStore) CreateSession(ctx context.Context, sess Session, ttl time.Duration) error {
	key := sessionKey(sess.ID)
	payload, err := marshalSession(sess)
	if err != nil {
		return err
	}

	pipe := s.cli.TxPipeline()
	pipe.Set(ctx, key, payload, ttl)
	pipe.SAdd(ctx, userSessionsKey(sess.UserID), sess.ID.String())
	pipe.Expire(ctx, userSessionsKey(sess.UserID), 35*24*time.Hour)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *RedisSessionStore) GetSession(ctx context.Context, sessionID uuid.UUID) (Session, error) {
	raw, err := s.cli.Get(ctx, sessionKey(sessionID)).Result()
	if err != nil {
		if err == goredis.Nil {
			return Session{}, ErrUnauthorized
		}
		return Session{}, fmt.Errorf("get session: %w", err)
	}

	var payload redisSessionPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return Session{}, fmt.Errorf("decode session payload: %w", err)
	}
	return decodeSession(payload)
}

func (s *RedisSessionStore) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	sess, err := s.GetSession(ctx, sessionID)
	if err != nil {
		if err == ErrUnauthorized {
			return nil
		}
		return err
	}

	pipe := s.cli.TxPipeline()
	pipe.Del(ctx, sessionKey(sessionID))
	pipe.SRem(ctx, userSessionsKey(sess.UserID), sessionID.String())
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *RedisSessionStore) DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	setKey := userSessionsKey(userID)
	ids, err := s.cli.SMembers(ctx, setKey).Result()
	if err != nil && err != goredis.Nil {
		return fmt.Errorf("get user sessions: %w", err)
	}

	pipe := s.cli.TxPipeline()
	for _, sid := range ids {
		pipe.Del(ctx, "session:"+sid)
	}
	pipe.Del(ctx, setKey)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("delete all user sessions: %w", err)
	}
	return nil
}

func (s *RedisSessionStore) DeleteAllUserSessionsExcept(ctx context.Context, userID, keepSessionID uuid.UUID) error {
	setKey := userSessionsKey(userID)
	ids, err := s.cli.SMembers(ctx, setKey).Result()
	if err != nil && err != goredis.Nil {
		return fmt.Errorf("get user sessions: %w", err)
	}

	keep := keepSessionID.String()
	pipe := s.cli.TxPipeline()
	for _, sid := range ids {
		if sid == keep {
			continue
		}
		pipe.Del(ctx, "session:"+sid)
		pipe.SRem(ctx, setKey, sid)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("delete all user sessions except current: %w", err)
	}
	return nil
}

func (s *RedisSessionStore) TouchSession(ctx context.Context, sessionID uuid.UUID, expiresAt, lastActivity time.Time, ttl time.Duration) error {
	sess, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}
	sess.ExpiresAt = expiresAt
	sess.LastActivityAt = lastActivity

	payload, err := marshalSession(sess)
	if err != nil {
		return err
	}

	if err := s.cli.Set(ctx, sessionKey(sessionID), payload, ttl).Err(); err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

func (s *RedisSessionStore) RevokeSession(ctx context.Context, sessionID uuid.UUID, revokedAt time.Time) error {
	sess, err := s.GetSession(ctx, sessionID)
	if err != nil {
		if err == ErrUnauthorized {
			return nil
		}
		return err
	}
	sess.RevokedAt = &revokedAt

	payload, err := marshalSession(sess)
	if err != nil {
		return err
	}
	if err := s.cli.Set(ctx, sessionKey(sessionID), payload, 5*time.Minute).Err(); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}
