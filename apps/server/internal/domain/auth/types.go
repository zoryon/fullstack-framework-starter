package auth

import (
	"time"

	"github.com/google/uuid"
	"github.com/golang-jwt/jwt/v5"
)

// Claims are signed into the short-lived access JWT.
type Claims struct {
	UserID        string `json:"user_id"`
	SessionID     string `json:"session_id"`
	OrgID         string `json:"org_id,omitempty"`
	ActiveVenueID string `json:"active_venue_id,omitempty"`
	Role          string `json:"role,omitempty"`
	Plan          string `json:"plan,omitempty"`
	jwt.RegisteredClaims
}

type User struct {
	ID                  uuid.UUID
	Email               string
	DisplayName         string
	PasswordHash        *string
	EmailVerified       bool
	IsActive            bool
	IsSuspended         bool
	FailedLoginAttempts int
	LockedUntil         *time.Time
}

type Membership struct {
	OrgID         uuid.UUID
	ActiveVenueID *uuid.UUID
	Role          string
	Plan          string
}

type RefreshToken struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	FamilyID        uuid.UUID
	SessionID       uuid.UUID
	TokenHash       string
	ExpiresAt       time.Time
	RevokedAt       *time.Time
	UsedAt          *time.Time
	PreviousTokenID *uuid.UUID
}

type OAuthAccount struct {
	Provider          string
	ProviderAccountID string
	AccessToken       string
	RefreshToken      string
	ExpiresAt         *time.Time
	Scope             string
	TokenType         string
}

// Session is the authoritative state for validating access JWTs.
type Session struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	OrgID             *uuid.UUID
	ActiveVenueID     *uuid.UUID
	Role              string
	Plan              string
	TokenHash         string
	IPAddress         string
	UserAgent         string
	MFAVerified       bool
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	LastActivityAt    time.Time
	RevokedAt         *time.Time
	CreatedAt         time.Time
}

type Actor struct {
	UserID        uuid.UUID
	SessionID     uuid.UUID
	OrgID         *uuid.UUID
	ActiveVenueID *uuid.UUID
	Role          string
	Plan          string
}

// TokenPair returns the access token and opaque refresh token.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	Session      Session
}

// RequestMeta carries request-scoped metadata used for audit fields.
type RequestMeta struct {
	IPAddress string
	UserAgent string
}
