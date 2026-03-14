package auth

import (
	"net/http"
	"time"

	domain "nutrico/server/internal/domain/auth"
)

const refreshCookieName = "refresh_token"
const oauthStateCookieName = "oauth_google_state"

type GoogleOAuthConfig struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
}

// Handler exposes all authentication HTTP endpoints.
type Handler struct {
	svc          *domain.Service
	cookieSecure bool
	oauth        GoogleOAuthConfig
	stateSecret  []byte
	oauthClient  *http.Client
}

func NewHandler(svc *domain.Service, cookieSecure bool, oauthCfg GoogleOAuthConfig, stateSecret string) *Handler {
	return &Handler{
		svc:          svc,
		cookieSecure: cookieSecure,
		oauth:        oauthCfg,
		stateSecret:  []byte(stateSecret),
		oauthClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/users", h.HandleRegister)
	mux.HandleFunc("POST /auth/sessions", h.HandleLogin)
	mux.HandleFunc("POST /auth/magic-links", h.HandleMagic)
	mux.HandleFunc("GET /auth/magic-links/{token}", h.HandleVerifyMagic)
	mux.HandleFunc("GET /auth/users/email-verifications/{token}", h.HandleVerifyEmail)
	mux.HandleFunc("POST /auth/oauth/google/sessions", h.HandleOAuthGoogleStart)
	mux.HandleFunc("GET /auth/oauth/google/callbacks", h.HandleOAuthGoogleCallback)
	mux.HandleFunc("PUT /auth/sessions/current/tokens", h.HandleRefresh)
	mux.HandleFunc("DELETE /auth/sessions/current", h.HandleLogout)
	mux.HandleFunc("POST /auth/password/reset-requests", h.HandleForgotPassword)
	mux.HandleFunc("PUT /auth/password", h.HandleResetPassword)
	mux.HandleFunc("PATCH /auth/password", h.HandleChangePassword)
}
