package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Service) Refresh(ctx context.Context, rawRefresh string, meta RequestMeta) (TokenPair, error) {
	hash := hashSHA256(rawRefresh)
	rt, err := s.repo.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TokenPair{}, ErrInvalidToken
		}
		return TokenPair{}, err
	}

	now := time.Now().UTC()
	if rt.RevokedAt != nil || rt.UsedAt != nil || now.After(rt.ExpiresAt) {
		_ = s.repo.RevokeRefreshFamily(ctx, rt.FamilyID)
		_ = s.store.DeleteSession(ctx, rt.SessionID)
		return TokenPair{}, ErrUnauthorized
	}

	u, err := s.repo.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return TokenPair{}, err
	}
	member, _ := s.repo.GetPrimaryMembership(ctx, u.ID)

	newPair, err := s.issueNewPair(ctx, u.ID, member, rt.FamilyID, rt.ID, meta, false)
	if err != nil {
		return TokenPair{}, err
	}

	newRT := RefreshToken{
		ID:              uuid.New(),
		UserID:          u.ID,
		FamilyID:        rt.FamilyID,
		SessionID:       newPair.Session.ID,
		TokenHash:       hashSHA256(newPair.RefreshToken),
		ExpiresAt:       now.Add(s.refreshTokenTTL),
		PreviousTokenID: &rt.ID,
	}

	if err := s.repo.RotateRefreshToken(ctx, rt.ID, newRT, meta.IPAddress, meta.UserAgent); err != nil {
		_ = s.store.DeleteSession(ctx, newPair.Session.ID)
		return TokenPair{}, err
	}
	_ = s.store.DeleteSession(ctx, rt.SessionID)
	return newPair, nil
}

func (s *Service) Logout(ctx context.Context, rawRefresh string) error {
	hash := hashSHA256(rawRefresh)
	rt, err := s.repo.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	_ = s.repo.RevokeRefreshTokenByID(ctx, rt.ID)
	_ = s.store.DeleteSession(ctx, rt.SessionID)
	return nil
}

func (s *Service) AuthenticateAccessToken(ctx context.Context, rawToken string) (Actor, error) {
	claims, err := s.jwt.Parse(rawToken)
	if err != nil {
		return Actor{}, err
	}

	sid, err := uuid.Parse(claims.SessionID)
	if err != nil {
		return Actor{}, ErrUnauthorized
	}
	sess, err := s.store.GetSession(ctx, sid)
	if err != nil {
		return Actor{}, ErrUnauthorized
	}

	now := time.Now().UTC()
	if sess.RevokedAt != nil || now.After(sess.ExpiresAt) || now.After(sess.AbsoluteExpiresAt) {
		return Actor{}, ErrUnauthorized
	}
	if sess.TokenHash != hashSHA256(rawToken) {
		return Actor{}, ErrUnauthorized
	}

	if shouldTouchSession(sess, now) {
		nextExpiry := now.Add(s.sessionTTL)
		if nextExpiry.After(sess.AbsoluteExpiresAt) {
			nextExpiry = sess.AbsoluteExpiresAt
		}
		_ = s.store.TouchSession(ctx, sess.ID, nextExpiry, now, time.Until(nextExpiry))
	}

	actor := Actor{
		UserID:    sess.UserID,
		SessionID: sess.ID,
		Role:      sess.Role,
		Plan:      sess.Plan,
	}
	actor.OrgID = sess.OrgID
	actor.ActiveVenueID = sess.ActiveVenueID
	return actor, nil
}

func shouldTouchSession(sess Session, now time.Time) bool {
	if now.Sub(sess.LastActivityAt) >= sessionTouchMinInterval {
		return true
	}
	return time.Until(sess.ExpiresAt) <= sessionTouchNearExpiryWindow
}

func (s *Service) issueNewPair(
	ctx context.Context,
	userID uuid.UUID,
	member Membership,
	familyID uuid.UUID,
	previousTokenID uuid.UUID,
	meta RequestMeta,
	persistRefresh bool,
) (TokenPair, error) {
	now := time.Now().UTC()
	if familyID == uuid.Nil {
		familyID = uuid.New()
	}
	sessionID := uuid.New()

	claims := Claims{UserID: userID.String(), SessionID: sessionID.String(), Role: member.Role, Plan: member.Plan}
	if member.OrgID != uuid.Nil {
		claims.OrgID = member.OrgID.String()
	}
	if member.ActiveVenueID != nil {
		claims.ActiveVenueID = member.ActiveVenueID.String()
	}

	access, err := s.jwt.Sign(claims)
	if err != nil {
		return TokenPair{}, err
	}
	refresh, err := randomTokenHex(32)
	if err != nil {
		return TokenPair{}, err
	}

	sess := Session{
		ID:                sessionID,
		UserID:            userID,
		Role:              member.Role,
		Plan:              member.Plan,
		TokenHash:         hashSHA256(access),
		IPAddress:         meta.IPAddress,
		UserAgent:         meta.UserAgent,
		MFAVerified:       false,
		ExpiresAt:         now.Add(s.sessionTTL),
		AbsoluteExpiresAt: now.Add(s.sessionAbsoluteTTL),
		LastActivityAt:    now,
		CreatedAt:         now,
	}
	if member.OrgID != uuid.Nil {
		org := member.OrgID
		sess.OrgID = &org
	}
	if member.ActiveVenueID != nil {
		sess.ActiveVenueID = member.ActiveVenueID
	}
	if err := s.store.CreateSession(ctx, sess, s.sessionTTL); err != nil {
		return TokenPair{}, err
	}

	if persistRefresh {
		rt := RefreshToken{ID: uuid.New(), UserID: userID, FamilyID: familyID, SessionID: sessionID, TokenHash: hashSHA256(refresh), ExpiresAt: now.Add(s.refreshTokenTTL)}
		if previousTokenID != uuid.Nil {
			rt.PreviousTokenID = &previousTokenID
		}
		if err := s.repo.CreateRefreshToken(ctx, rt, meta.IPAddress, meta.UserAgent); err != nil {
			_ = s.store.DeleteSession(ctx, sessionID)
			return TokenPair{}, err
		}
	}

	return TokenPair{AccessToken: access, RefreshToken: refresh, Session: sess}, nil
}
