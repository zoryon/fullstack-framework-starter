package auth

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func marshalSession(sess Session) (string, error) {
	payload := redisSessionPayload{
		ID:                sess.ID.String(),
		UserID:            sess.UserID.String(),
		Role:              sess.Role,
		Plan:              sess.Plan,
		TokenHash:         sess.TokenHash,
		IPAddress:         sess.IPAddress,
		UserAgent:         sess.UserAgent,
		MFAVerified:       sess.MFAVerified,
		ExpiresAt:         sess.ExpiresAt.Unix(),
		AbsoluteExpiresAt: sess.AbsoluteExpiresAt.Unix(),
		LastActivityAt:    sess.LastActivityAt.Unix(),
		CreatedAt:         sess.CreatedAt.Unix(),
	}
	if sess.OrgID != nil {
		s := sess.OrgID.String()
		payload.OrgID = &s
	}
	if sess.ActiveVenueID != nil {
		s := sess.ActiveVenueID.String()
		payload.ActiveVenueID = &s
	}
	if sess.RevokedAt != nil {
		r := sess.RevokedAt.Unix()
		payload.RevokedAt = &r
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal session: %w", err)
	}
	return string(b), nil
}

func decodeSession(in redisSessionPayload) (Session, error) {
	sID, err := uuid.Parse(in.ID)
	if err != nil {
		return Session{}, fmt.Errorf("parse session id: %w", err)
	}
	uID, err := uuid.Parse(in.UserID)
	if err != nil {
		return Session{}, fmt.Errorf("parse user id: %w", err)
	}

	out := Session{
		ID:                sID,
		UserID:            uID,
		Role:              in.Role,
		Plan:              in.Plan,
		TokenHash:         in.TokenHash,
		IPAddress:         in.IPAddress,
		UserAgent:         in.UserAgent,
		MFAVerified:       in.MFAVerified,
		ExpiresAt:         time.Unix(in.ExpiresAt, 0).UTC(),
		AbsoluteExpiresAt: time.Unix(in.AbsoluteExpiresAt, 0).UTC(),
		LastActivityAt:    time.Unix(in.LastActivityAt, 0).UTC(),
		CreatedAt:         time.Unix(in.CreatedAt, 0).UTC(),
	}

	if in.OrgID != nil {
		v, err := uuid.Parse(*in.OrgID)
		if err == nil {
			out.OrgID = &v
		}
	}
	if in.ActiveVenueID != nil {
		v, err := uuid.Parse(*in.ActiveVenueID)
		if err == nil {
			out.ActiveVenueID = &v
		}
	}
	if in.RevokedAt != nil {
		t := time.Unix(*in.RevokedAt, 0).UTC()
		out.RevokedAt = &t
	}
	return out, nil
}

func sessionKey(sessionID uuid.UUID) string {
	return "session:" + sessionID.String()
}

func userSessionsKey(userID uuid.UUID) string {
	return "user_sessions:" + userID.String()
}
