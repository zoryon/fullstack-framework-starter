package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type oauthStateCookie struct {
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
	ExpiresAt    int64  `json:"expires_at"`
}

func (h *Handler) setSignedOAuthStateCookie(w http.ResponseWriter, payload oauthStateCookie) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	data := base64.RawURLEncoding.EncodeToString(raw)
	sig := h.signValue(data)

	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    data + "." + sig,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(payload.ExpiresAt, 0).UTC(),
	})
	return nil
}

func (h *Handler) readSignedOAuthStateCookie(r *http.Request) (oauthStateCookie, error) {
	c, err := r.Cookie(oauthStateCookieName)
	if err != nil {
		return oauthStateCookie{}, err
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return oauthStateCookie{}, errors.New("invalid oauth state cookie")
	}

	if !hmac.Equal([]byte(h.signValue(parts[0])), []byte(parts[1])) {
		return oauthStateCookie{}, errors.New("oauth state signature mismatch")
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return oauthStateCookie{}, err
	}
	var payload oauthStateCookie
	if err := json.Unmarshal(raw, &payload); err != nil {
		return oauthStateCookie{}, err
	}
	return payload, nil
}

func (h *Handler) clearOAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
	})
}

func (h *Handler) signValue(v string) string {
	mac := hmac.New(sha256.New, h.stateSecret)
	mac.Write([]byte(v))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
