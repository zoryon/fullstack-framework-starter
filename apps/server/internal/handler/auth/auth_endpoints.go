package auth

import (
	"net/http"
	"strings"

	domain "nutrico/server/internal/domain/auth"
	"nutrico/server/internal/platform/response"
)

func (h *Handler) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	actor, ok := domain.ActorFromContext(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	err := h.svc.ChangePassword(r.Context(), actor, req.CurrentPassword, req.NewPassword)
	if err != nil {
		mapAuthError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	err := h.svc.Register(r.Context(), req.Email, req.Password, req.DisplayName)
	if err != nil {
		mapAuthError(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	pair, err := h.svc.Login(r.Context(), req.Email, req.Password, requestMeta(r))
	if err != nil {
		mapAuthError(w, err)
		return
	}

	h.setRefreshCookie(w, pair.RefreshToken)
	response.JSON(w, http.StatusOK, map[string]string{"access_token": pair.AccessToken})
}

func (h *Handler) HandleMagic(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.RequestMagicLink(r.Context(), req.Email); err != nil {
		mapAuthError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) HandleVerifyMagic(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.PathValue("token"))
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if token == "" {
		response.Error(w, http.StatusBadRequest, "missing_token")
		return
	}

	pair, err := h.svc.VerifyMagicLink(r.Context(), token, requestMeta(r))
	if err != nil {
		mapAuthError(w, err)
		return
	}
	h.setRefreshCookie(w, pair.RefreshToken)
	response.JSON(w, http.StatusOK, map[string]string{"access_token": pair.AccessToken})
}

func (h *Handler) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.PathValue("token"))
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if token == "" {
		response.Error(w, http.StatusBadRequest, "missing_token")
		return
	}
	if err := h.svc.VerifyEmail(r.Context(), token); err != nil {
		mapAuthError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	refresh, err := readRefreshCookie(r)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	pair, err := h.svc.Refresh(r.Context(), refresh, requestMeta(r))
	if err != nil {
		h.clearRefreshCookie(w)
		mapAuthError(w, err)
		return
	}
	h.setRefreshCookie(w, pair.RefreshToken)
	response.JSON(w, http.StatusOK, map[string]string{"access_token": pair.AccessToken})
}

func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	refresh, _ := readRefreshCookie(r)
	if refresh != "" {
		_ = h.svc.Logout(r.Context(), refresh)
	}
	h.clearRefreshCookie(w)
	response.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.ForgotPassword(r.Context(), req.Email); err != nil {
		mapAuthError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		mapAuthError(w, err)
		return
	}
	h.clearRefreshCookie(w)
	response.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
