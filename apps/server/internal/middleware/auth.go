package middleware

import (
	"net/http"
	"strings"

	"nutrico/server/internal/domain/auth"
	"nutrico/server/internal/platform/response"
)

// AuthMiddleware validates JWT + Redis session and injects actor into context.
type AuthMiddleware struct {
	Service *auth.Service
}

func (m AuthMiddleware) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r.Header.Get("Authorization"))
		if raw == "" {
			response.Error(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		actor, err := m.Service.AuthenticateAccessToken(r.Context(), raw)
		if err != nil {
			response.Error(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		next.ServeHTTP(w, r.WithContext(auth.WithActor(r.Context(), actor)))
	})
}

func bearerToken(v string) string {
	if v == "" {
		return ""
	}
	parts := strings.SplitN(v, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
