package auth

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	domain "nutrico/server/internal/domain/auth"
	"nutrico/server/internal/platform/response"
)

func (h *Handler) setRefreshCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().UTC().Add(30 * 24 * time.Hour),
	})
}

func (h *Handler) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
	})
}

func readRefreshCookie(r *http.Request) (string, error) {
	c, err := r.Cookie(refreshCookieName)
	if err != nil {
		return "", err
	}
	if c.Value == "" {
		return "", errors.New("missing refresh token")
	}
	return c.Value, nil
}

func requestMeta(r *http.Request) domain.RequestMeta {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		ip := strings.TrimSpace(strings.Split(xff, ",")[0])
		if ip != "" {
			return domain.RequestMeta{IPAddress: ip, UserAgent: r.UserAgent()}
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return domain.RequestMeta{IPAddress: xri, UserAgent: r.UserAgent()}
	}

	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	return domain.RequestMeta{IPAddress: ip, UserAgent: r.UserAgent()}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		response.Error(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func mapAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrConflict):
		response.Error(w, http.StatusConflict, "resource_conflict")
	case errors.Is(err, domain.ErrEmailNotVerified):
		response.Error(w, http.StatusForbidden, "email_not_verified")
	case errors.Is(err, domain.ErrLocked):
		response.Error(w, http.StatusTooManyRequests, "account_locked")
	case errors.Is(err, domain.ErrInvalidCredentials), errors.Is(err, domain.ErrUnauthorized):
		response.Error(w, http.StatusUnauthorized, "invalid_credentials")
	case errors.Is(err, domain.ErrInvalidToken), errors.Is(err, domain.ErrExpiredToken):
		response.Error(w, http.StatusUnauthorized, "invalid_token")
	default:
		response.Error(w, http.StatusInternalServerError, "internal_error")
	}
}
