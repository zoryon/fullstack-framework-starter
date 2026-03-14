package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (s *Service) ForgotPassword(ctx context.Context, email string) error {
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
	if err := s.store.StorePasswordResetToken(ctx, hashSHA256(raw), u.ID, s.passwordResetTTL); err != nil {
		return err
	}
	if err := s.sendPasswordReset(ctx, email, raw); err != nil {
		return err
	}
	return nil
}

func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
	if !validatePasswordStrength(newPassword) {
		return ErrInvalidCredentials
	}
	uid, err := s.store.ConsumePasswordResetToken(ctx, hashSHA256(token))
	if err != nil {
		return err
	}

	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.repo.UpdatePassword(ctx, uid, hash); err != nil {
		return err
	}

	_ = s.repo.RevokeAllUserRefreshTokens(ctx, uid)
	_ = s.store.DeleteAllUserSessions(ctx, uid)
	return nil
}

func (s *Service) ChangePassword(ctx context.Context, actor Actor, currentPassword, newPassword string) error {
	if !validatePasswordStrength(newPassword) {
		return ErrInvalidCredentials
	}

	u, err := s.repo.GetUserByID(ctx, actor.UserID)
	if err != nil {
		return err
	}
	if u.PasswordHash == nil || comparePassword(*u.PasswordHash, currentPassword) != nil {
		return ErrInvalidCredentials
	}

	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.repo.UpdatePassword(ctx, actor.UserID, hash); err != nil {
		return err
	}

	_ = s.repo.RevokeAllUserRefreshTokensExceptSession(ctx, actor.UserID, actor.SessionID)
	_ = s.store.DeleteAllUserSessionsExcept(ctx, actor.UserID, actor.SessionID)
	return nil
}

func (s *Service) sendEmailVerification(ctx context.Context, toEmail, token string) error {
	if s.mail == nil {
		return fmt.Errorf("email sender not configured")
	}
	verifyURL := s.apiURL("/auth/users/email-verifications/") + url.PathEscape(token)
	body := "Welcome to Nutrico!\n\n" +
		"Please verify your email by opening this link:\n" + verifyURL + "\n\n" +
		"If you did not create this account, ignore this message."
	if err := s.mail.Send(ctx, toEmail, "Verify your Nutrico email", body); err != nil {
		return fmt.Errorf("send email verification: %w", err)
	}
	return nil
}

func (s *Service) sendMagicLink(ctx context.Context, toEmail, token string) error {
	if s.mail == nil {
		return fmt.Errorf("email sender not configured")
	}
	magicURL := s.apiURL("/auth/magic-links/") + url.PathEscape(token)
	body := "Use this magic link to sign in to Nutrico:\n\n" + magicURL + "\n\n" +
		"This link expires shortly. If you did not request it, ignore this message."
	if err := s.mail.Send(ctx, toEmail, "Your Nutrico magic link", body); err != nil {
		return fmt.Errorf("send magic link: %w", err)
	}
	return nil
}

func (s *Service) sendPasswordReset(ctx context.Context, toEmail, token string) error {
	if s.mail == nil {
		return fmt.Errorf("email sender not configured")
	}
	body := "You requested a Nutrico password reset.\n\n" +
		"Reset token:\n" + token + "\n\n" +
		"Call PUT /auth/password with JSON body {\"token\":\"<token>\",\"new_password\":\"...\"}.\n\n" +
		"If you did not request this, ignore this message."
	if err := s.mail.Send(ctx, toEmail, "Nutrico password reset", body); err != nil {
		return fmt.Errorf("send password reset email: %w", err)
	}
	return nil
}

func (s *Service) apiURL(path string) string {
	base := strings.TrimRight(strings.TrimSpace(s.baseURL), "/")
	if base == "" {
		base = "http://localhost"
	}
	if strings.HasSuffix(base, "/api") {
		return base + path
	}
	return base + "/api" + path
}
