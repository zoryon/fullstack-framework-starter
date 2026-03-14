package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Service) Register(ctx context.Context, email, password, displayName string) error {
	email = normalizeEmail(email)
	if email == "" || !validatePasswordStrength(password) {
		return ErrInvalidCredentials
	}

	_, err := s.repo.GetUserByEmail(ctx, email)
	if err == nil {
		return ErrConflict
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	hash, err := hashPassword(password)
	if err != nil {
		return err
	}

	u, err := s.repo.CreateUser(ctx, email, displayName, hash)
	if err != nil {
		return err
	}

	raw, err := randomTokenHex(32)
	if err != nil {
		return err
	}
	if err := s.store.StoreEmailVerificationToken(ctx, hashSHA256(raw), u.ID, s.emailVerifyTTL); err != nil {
		return fmt.Errorf("store email verification token: %w", err)
	}

	if err := s.sendEmailVerification(ctx, email, raw); err != nil {
		return err
	}
	return nil
}

func (s *Service) Login(ctx context.Context, email, password string, meta RequestMeta) (TokenPair, error) {
	email = normalizeEmail(email)
	u, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TokenPair{}, ErrInvalidCredentials
		}
		return TokenPair{}, err
	}

	if u.LockedUntil != nil && u.LockedUntil.After(time.Now().UTC()) {
		return TokenPair{}, ErrLocked
	}
	if !u.IsActive || u.IsSuspended {
		return TokenPair{}, ErrUnauthorized
	}
	if !u.EmailVerified {
		return TokenPair{}, ErrEmailNotVerified
	}
	if u.PasswordHash == nil {
		return TokenPair{}, ErrInvalidCredentials
	}

	if err := comparePassword(*u.PasswordHash, password); err != nil {
		_ = s.repo.IncrementFailedLogin(ctx, u.ID, 5, 15*time.Minute)
		return TokenPair{}, ErrInvalidCredentials
	}
	_ = s.repo.ResetFailedLogin(ctx, u.ID)

	member, _ := s.repo.GetPrimaryMembership(ctx, u.ID)
	return s.issueNewPair(ctx, u.ID, member, uuid.Nil, uuid.Nil, meta, true)
}

func (s *Service) RequestMagicLink(ctx context.Context, email string) error {
	email = normalizeEmail(email)
	u, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}

	raw, err := randomTokenHex(32)
	if err != nil {
		return err
	}
	if err := s.store.StoreMagicToken(ctx, hashSHA256(raw), u.ID, s.magicLinkTTL); err != nil {
		return fmt.Errorf("store magic token: %w", err)
	}
	if err := s.sendMagicLink(ctx, email, raw); err != nil {
		return err
	}
	return nil
}

func (s *Service) VerifyMagicLink(ctx context.Context, token string, meta RequestMeta) (TokenPair, error) {
	uid, err := s.store.ConsumeMagicToken(ctx, hashSHA256(token))
	if err != nil {
		return TokenPair{}, err
	}

	u, err := s.repo.GetUserByID(ctx, uid)
	if err != nil {
		return TokenPair{}, err
	}
	if !u.EmailVerified {
		_ = s.repo.MarkEmailVerified(ctx, u.ID)
	}

	member, _ := s.repo.GetPrimaryMembership(ctx, u.ID)
	return s.issueNewPair(ctx, u.ID, member, uuid.Nil, uuid.Nil, meta, true)
}

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	uid, err := s.store.ConsumeEmailVerificationToken(ctx, hashSHA256(token))
	if err != nil {
		return err
	}
	return s.repo.MarkEmailVerified(ctx, uid)
}

func (s *Service) OAuthLogin(ctx context.Context, account OAuthAccount, email, displayName string, meta RequestMeta) (TokenPair, error) {
	if account.Provider == "" || account.ProviderAccountID == "" {
		return TokenPair{}, ErrUnauthorized
	}

	email = normalizeEmail(email)
	if email == "" {
		return TokenPair{}, ErrUnauthorized
	}

	u, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return TokenPair{}, err
		}
		u, err = s.repo.CreateOAuthUser(ctx, email, displayName)
		if err != nil {
			return TokenPair{}, err
		}
	}

	if !u.IsActive || u.IsSuspended {
		return TokenPair{}, ErrUnauthorized
	}
	if !u.EmailVerified {
		_ = s.repo.MarkEmailVerified(ctx, u.ID)
	}

	if err := s.repo.UpsertOAuthAccount(ctx, u.ID, account); err != nil {
		return TokenPair{}, err
	}

	member, _ := s.repo.GetPrimaryMembership(ctx, u.ID)
	return s.issueNewPair(ctx, u.ID, member, uuid.Nil, uuid.Nil, meta, true)
}
