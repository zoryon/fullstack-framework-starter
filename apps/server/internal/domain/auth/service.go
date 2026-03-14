package auth

import (
	"context"
	"time"
)

const sessionTouchMinInterval = 60 * time.Second
const sessionTouchNearExpiryWindow = 2 * time.Minute

// Service orchestrates authentication flows across Postgres and Redis.
type Service struct {
	repo  Repository
	store SessionStore
	jwt   *JWTManager
	mail  Mailer

	baseURL string

	accessTokenTTL     time.Duration
	refreshTokenTTL    time.Duration
	sessionTTL         time.Duration
	sessionAbsoluteTTL time.Duration
	emailVerifyTTL     time.Duration
	magicLinkTTL       time.Duration
	passwordResetTTL   time.Duration
}

type ServiceConfig struct {
	BaseURL            string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	SessionTTL         time.Duration
	SessionAbsoluteTTL time.Duration
	EmailVerifyTTL     time.Duration
	MagicLinkTTL       time.Duration
	PasswordResetTTL   time.Duration
}

// Mailer sends transactional auth emails.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

func NewService(repo Repository, store SessionStore, jwt *JWTManager, mailer Mailer, cfg ServiceConfig) *Service {
	return &Service{
		repo:               repo,
		store:              store,
		jwt:                jwt,
		mail:               mailer,
		baseURL:            cfg.BaseURL,
		accessTokenTTL:     cfg.AccessTokenTTL,
		refreshTokenTTL:    cfg.RefreshTokenTTL,
		sessionTTL:         cfg.SessionTTL,
		sessionAbsoluteTTL: cfg.SessionAbsoluteTTL,
		emailVerifyTTL:     cfg.EmailVerifyTTL,
		magicLinkTTL:       cfg.MagicLinkTTL,
		passwordResetTTL:   cfg.PasswordResetTTL,
	}
}
