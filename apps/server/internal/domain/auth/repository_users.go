package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (r *SQLRepository) CreateUser(ctx context.Context, email, displayName, passwordHash string) (User, error) {
	q := `
		INSERT INTO users (email, display_name, password_hash, email_verified)
		VALUES ($1, $2, $3, false)
		RETURNING id, email, COALESCE(display_name, ''), password_hash, email_verified, is_active, is_suspended, failed_login_attempts, locked_until
	`
	return scanUser(r.pool.QueryRow(ctx, q, email, displayName, passwordHash))
}

func (r *SQLRepository) CreateOAuthUser(ctx context.Context, email, displayName string) (User, error) {
	q := `
		INSERT INTO users (email, display_name, email_verified, password_hash)
		VALUES ($1, $2, true, NULL)
		RETURNING id, email, COALESCE(display_name, ''), password_hash, email_verified, is_active, is_suspended, failed_login_attempts, locked_until
	`
	return scanUser(r.pool.QueryRow(ctx, q, email, displayName))
}

func (r *SQLRepository) GetUserByEmail(ctx context.Context, email string) (User, error) {
	q := `
		SELECT id, email, COALESCE(display_name, ''), password_hash, email_verified, is_active, is_suspended, failed_login_attempts, locked_until
		FROM users
		WHERE email = $1 AND deleted_at IS NULL
	`
	return scanUser(r.pool.QueryRow(ctx, q, email))
}

func (r *SQLRepository) GetUserByID(ctx context.Context, userID uuid.UUID) (User, error) {
	q := `
		SELECT id, email, COALESCE(display_name, ''), password_hash, email_verified, is_active, is_suspended, failed_login_attempts, locked_until
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`
	return scanUser(r.pool.QueryRow(ctx, q, userID))
}

func (r *SQLRepository) GetPrimaryMembership(ctx context.Context, userID uuid.UUID) (Membership, error) {
	q := `
		SELECT
			m.org_id,
			(
				SELECT v.id
				FROM venues v
				WHERE v.org_id = m.org_id AND v.is_active = true AND v.deleted_at IS NULL
				ORDER BY v.created_at ASC
				LIMIT 1
			) AS active_venue_id,
			m.role::text,
			o.plan::text
		FROM org_memberships m
		JOIN organisations o ON o.id = m.org_id
		WHERE m.user_id = $1 AND m.is_active = true AND o.deleted_at IS NULL
		ORDER BY m.created_at ASC
		LIMIT 1
	`
	var out Membership
	var venue *uuid.UUID
	err := r.pool.QueryRow(ctx, q, userID).Scan(&out.OrgID, &venue, &out.Role, &out.Plan)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Membership{}, pgx.ErrNoRows
		}
		return Membership{}, fmt.Errorf("get membership: %w", err)
	}
	out.ActiveVenueID = venue
	return out, nil
}

func (r *SQLRepository) MarkEmailVerified(ctx context.Context, userID uuid.UUID) error {
	q := `
		UPDATE users
		SET email_verified = true,
			email_verification_token = NULL,
			email_verification_expires = NULL,
			updated_at = now()
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("mark email verified: %w", err)
	}
	return nil
}

func (r *SQLRepository) UpsertOAuthAccount(ctx context.Context, userID uuid.UUID, account OAuthAccount) error {
	q := `
		INSERT INTO oauth_accounts (
			user_id, provider, provider_account_id,
			access_token, refresh_token, expires_at, scope, token_type
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (provider, provider_account_id)
		DO UPDATE
		SET user_id = EXCLUDED.user_id,
			access_token = EXCLUDED.access_token,
			refresh_token = EXCLUDED.refresh_token,
			expires_at = EXCLUDED.expires_at,
			scope = EXCLUDED.scope,
			token_type = EXCLUDED.token_type,
			updated_at = now()
	`
	_, err := r.pool.Exec(ctx, q,
		userID,
		account.Provider,
		account.ProviderAccountID,
		nullableText(account.AccessToken),
		nullableText(account.RefreshToken),
		account.ExpiresAt,
		nullableText(account.Scope),
		nullableText(account.TokenType),
	)
	if err != nil {
		return fmt.Errorf("upsert oauth account: %w", err)
	}
	return nil
}

func (r *SQLRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	q := `
		UPDATE users
		SET password_hash = $2,
			password_reset_token = NULL,
			password_reset_expires = NULL,
			failed_login_attempts = 0,
			locked_until = NULL,
			updated_at = now()
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, q, userID, passwordHash)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	return nil
}

func (r *SQLRepository) IncrementFailedLogin(ctx context.Context, userID uuid.UUID, maxAttempts int, lockFor time.Duration) error {
	q := `
		UPDATE users
		SET failed_login_attempts = failed_login_attempts + 1,
			locked_until = CASE
				WHEN failed_login_attempts + 1 >= $2 THEN now() + $3::interval
				ELSE locked_until
			END,
			updated_at = now()
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, q, userID, maxAttempts, formatInterval(lockFor))
	if err != nil {
		return fmt.Errorf("increment failed login: %w", err)
	}
	return nil
}

func (r *SQLRepository) ResetFailedLogin(ctx context.Context, userID uuid.UUID) error {
	q := `
		UPDATE users
		SET failed_login_attempts = 0,
			locked_until = NULL,
			updated_at = now()
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("reset failed login: %w", err)
	}
	return nil
}
