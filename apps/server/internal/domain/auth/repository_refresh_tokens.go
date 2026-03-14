package auth

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (r *SQLRepository) CreateRefreshToken(ctx context.Context, token RefreshToken, ip, ua string) error {
	q := `
		INSERT INTO refresh_tokens (
			id, user_id, token_hash, family_id, previous_token_id,
			session_id, expires_at, ip_address, user_agent
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`
	_, err := r.pool.Exec(ctx, q,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.FamilyID,
		token.PreviousTokenID,
		token.SessionID,
		token.ExpiresAt,
		nullableIP(ip),
		ua,
	)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

func (r *SQLRepository) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (RefreshToken, error) {
	q := `
		SELECT id, user_id, family_id, session_id, token_hash, expires_at, revoked_at, used_at, previous_token_id
		FROM refresh_tokens
		WHERE token_hash = $1
	`
	var rt RefreshToken
	err := r.pool.QueryRow(ctx, q, tokenHash).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.FamilyID,
		&rt.SessionID,
		&rt.TokenHash,
		&rt.ExpiresAt,
		&rt.RevokedAt,
		&rt.UsedAt,
		&rt.PreviousTokenID,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return RefreshToken{}, pgx.ErrNoRows
		}
		return RefreshToken{}, fmt.Errorf("get refresh token by hash: %w", err)
	}
	return rt, nil
}

func (r *SQLRepository) RotateRefreshToken(ctx context.Context, oldTokenID uuid.UUID, newToken RefreshToken, ip, ua string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin rotate tx: %w", err)
	}
	defer tx.Rollback(ctx)

	qLock := `
		SELECT id
		FROM refresh_tokens
		WHERE id = $1
		FOR UPDATE
	`
	if _, err := tx.Exec(ctx, qLock, oldTokenID); err != nil {
		return fmt.Errorf("lock refresh token: %w", err)
	}

	qRevokeOld := `
		UPDATE refresh_tokens
		SET revoked_at = now(), used_at = now()
		WHERE id = $1
	`
	if _, err := tx.Exec(ctx, qRevokeOld, oldTokenID); err != nil {
		return fmt.Errorf("revoke old refresh token: %w", err)
	}

	qInsert := `
		INSERT INTO refresh_tokens (
			id, user_id, token_hash, family_id, previous_token_id,
			session_id, expires_at, ip_address, user_agent
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`
	if _, err := tx.Exec(ctx, qInsert,
		newToken.ID,
		newToken.UserID,
		newToken.TokenHash,
		newToken.FamilyID,
		newToken.PreviousTokenID,
		newToken.SessionID,
		newToken.ExpiresAt,
		nullableIP(ip),
		ua,
	); err != nil {
		return fmt.Errorf("insert rotated refresh token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit rotate tx: %w", err)
	}
	return nil
}

func (r *SQLRepository) RevokeRefreshTokenByID(ctx context.Context, tokenID uuid.UUID) error {
	q := `
		UPDATE refresh_tokens
		SET revoked_at = now()
		WHERE id = $1 AND revoked_at IS NULL
	`
	_, err := r.pool.Exec(ctx, q, tokenID)
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

func (r *SQLRepository) RevokeRefreshFamily(ctx context.Context, familyID uuid.UUID) error {
	q := `
		UPDATE refresh_tokens
		SET revoked_at = now()
		WHERE family_id = $1 AND revoked_at IS NULL
	`
	_, err := r.pool.Exec(ctx, q, familyID)
	if err != nil {
		return fmt.Errorf("revoke refresh family: %w", err)
	}
	return nil
}

func (r *SQLRepository) RevokeAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	q := `
		UPDATE refresh_tokens
		SET revoked_at = now()
		WHERE user_id = $1 AND revoked_at IS NULL
	`
	_, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("revoke all user refresh tokens: %w", err)
	}
	return nil
}

func (r *SQLRepository) RevokeAllUserRefreshTokensExceptSession(ctx context.Context, userID, keepSessionID uuid.UUID) error {
	q := `
		UPDATE refresh_tokens
		SET revoked_at = now()
		WHERE user_id = $1
			AND session_id <> $2
			AND revoked_at IS NULL
	`
	_, err := r.pool.Exec(ctx, q, userID, keepSessionID)
	if err != nil {
		return fmt.Errorf("revoke all user refresh tokens except session: %w", err)
	}
	return nil
}
