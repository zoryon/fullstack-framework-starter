package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	domain "nutrico/server/internal/domain/auth"
	"nutrico/server/internal/platform/response"
)

type googleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
}

type googleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

func (h *Handler) HandleOAuthGoogleStart(w http.ResponseWriter, r *http.Request) {
	if !h.oauth.Enabled {
		response.Error(w, http.StatusNotFound, "not_enabled")
		return
	}

	state, err := randomURLToken(24)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "internal_error")
		return
	}
	codeVerifier, err := randomURLToken(32)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "internal_error")
		return
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	if err := h.setSignedOAuthStateCookie(w, oauthStateCookie{
		State:        state,
		CodeVerifier: codeVerifier,
		ExpiresAt:    expiresAt.Unix(),
	}); err != nil {
		response.Error(w, http.StatusInternalServerError, "internal_error")
		return
	}

	v := url.Values{}
	v.Set("client_id", h.oauth.ClientID)
	v.Set("redirect_uri", h.oauth.RedirectURL)
	v.Set("response_type", "code")
	v.Set("scope", "openid email profile")
	v.Set("state", state)
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")
	v.Set("access_type", "offline")
	v.Set("prompt", "consent")

	authURL := h.oauth.AuthURL + "?" + v.Encode()
	response.JSON(w, http.StatusOK, map[string]string{"auth_url": authURL})
}

func (h *Handler) HandleOAuthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if !h.oauth.Enabled {
		response.Error(w, http.StatusNotFound, "not_enabled")
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		response.Error(w, http.StatusBadRequest, "invalid_oauth_callback")
		return
	}

	oauthState, err := h.readSignedOAuthStateCookie(r)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "invalid_oauth_state")
		return
	}
	if oauthState.State != state || time.Now().UTC().Unix() > oauthState.ExpiresAt {
		h.clearOAuthStateCookie(w)
		response.Error(w, http.StatusUnauthorized, "invalid_oauth_state")
		return
	}

	tok, err := h.exchangeGoogleCode(r.Context(), code, oauthState.CodeVerifier)
	if err != nil {
		h.clearOAuthStateCookie(w)
		response.Error(w, http.StatusUnauthorized, "invalid_oauth_code")
		return
	}

	profile, err := h.fetchGoogleUserProfile(r.Context(), tok.AccessToken)
	if err != nil {
		h.clearOAuthStateCookie(w)
		response.Error(w, http.StatusUnauthorized, "invalid_oauth_profile")
		return
	}
	if profile.Email == "" || profile.Sub == "" {
		h.clearOAuthStateCookie(w)
		response.Error(w, http.StatusUnauthorized, "invalid_oauth_profile")
		return
	}

	var expiresAt *time.Time
	if tok.ExpiresIn > 0 {
		t := time.Now().UTC().Add(time.Duration(tok.ExpiresIn) * time.Second)
		expiresAt = &t
	}

	pair, err := h.svc.OAuthLogin(r.Context(), domain.OAuthAccount{
		Provider:          "google",
		ProviderAccountID: profile.Sub,
		AccessToken:       tok.AccessToken,
		RefreshToken:      tok.RefreshToken,
		ExpiresAt:         expiresAt,
		Scope:             tok.Scope,
		TokenType:         tok.TokenType,
	}, profile.Email, profile.Name, requestMeta(r))
	if err != nil {
		h.clearOAuthStateCookie(w)
		mapAuthError(w, err)
		return
	}

	h.clearOAuthStateCookie(w)
	h.setRefreshCookie(w, pair.RefreshToken)
	response.JSON(w, http.StatusOK, map[string]string{"access_token": pair.AccessToken})
}

func (h *Handler) exchangeGoogleCode(ctx context.Context, code, codeVerifier string) (googleTokenResponse, error) {
	values := url.Values{}
	values.Set("client_id", h.oauth.ClientID)
	values.Set("client_secret", h.oauth.ClientSecret)
	values.Set("grant_type", "authorization_code")
	values.Set("code", code)
	values.Set("redirect_uri", h.oauth.RedirectURL)
	values.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.oauth.TokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return googleTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.oauthClient.Do(req)
	if err != nil {
		return googleTokenResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return googleTokenResponse{}, fmt.Errorf("token exchange status: %d", resp.StatusCode)
	}

	var out googleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return googleTokenResponse{}, err
	}
	if out.AccessToken == "" {
		return googleTokenResponse{}, errors.New("missing access token")
	}
	return out, nil
}

func (h *Handler) fetchGoogleUserProfile(ctx context.Context, accessToken string) (googleUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.oauth.UserInfoURL, nil)
	if err != nil {
		return googleUserInfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := h.oauthClient.Do(req)
	if err != nil {
		return googleUserInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return googleUserInfo{}, fmt.Errorf("userinfo status %d: %s", resp.StatusCode, string(body))
	}

	var info googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return googleUserInfo{}, err
	}
	if !info.EmailVerified {
		return googleUserInfo{}, errors.New("google email not verified")
	}
	return info, nil
}

func randomURLToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
