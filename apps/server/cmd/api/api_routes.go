package main

import (
	"context"
	"net/http"
	"time"

	handlerauth "nutrico/server/internal/handler/auth"
	"nutrico/server/internal/middleware"
	"nutrico/server/internal/platform/config"

	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
)

func registerAPIRoutes(
	mux *http.ServeMux,
	cfg config.Config,
	pg *pgxpool.Pool,
	rdb *goredis.Client,
	authH *handlerauth.Handler,
	authMW middleware.AuthMiddleware,
	rl *middleware.IPRateLimiter,
) {
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		checkCtx, cancel := context.WithTimeout(r.Context(), cfg.ReadyCheckTimeout)
		defer cancel()

		if err := pg.Ping(checkCtx); err != nil {
			http.Error(w, "postgres_unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := rdb.Ping(checkCtx).Err(); err != nil {
			http.Error(w, "redis_unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	mux.Handle("POST /auth/users", rl.Limit(5, time.Minute)(http.HandlerFunc(authH.HandleRegister)))
	mux.Handle("POST /auth/sessions", rl.Limit(10, time.Minute)(http.HandlerFunc(authH.HandleLogin)))
	mux.Handle("POST /auth/magic-links", rl.Limit(5, time.Minute)(http.HandlerFunc(authH.HandleMagic)))
	mux.Handle("POST /auth/oauth/google/sessions", rl.Limit(5, time.Minute)(http.HandlerFunc(authH.HandleOAuthGoogleStart)))
	mux.HandleFunc("GET /auth/oauth/google/callbacks", authH.HandleOAuthGoogleCallback)
	mux.HandleFunc("GET /auth/magic-links/{token}", authH.HandleVerifyMagic)
	mux.HandleFunc("GET /auth/users/email-verifications/{token}", authH.HandleVerifyEmail)
	mux.HandleFunc("PUT /auth/sessions/current/tokens", authH.HandleRefresh)
	mux.HandleFunc("DELETE /auth/sessions/current", authH.HandleLogout)
	mux.HandleFunc("POST /auth/password/reset-requests", authH.HandleForgotPassword)
	mux.HandleFunc("PUT /auth/password", authH.HandleResetPassword)
	mux.Handle("PATCH /auth/password", authMW.Require(http.HandlerFunc(authH.HandleChangePassword)))

	mux.Handle("GET /swagger", localOnly(http.HandlerFunc(handleSwaggerUI)))
	mux.Handle("GET /swagger/", localOnly(http.HandlerFunc(handleSwaggerUI)))
	mux.Handle("GET /swagger/index.html", localOnly(http.HandlerFunc(handleSwaggerUI)))
	mux.Handle("GET /swagger/openapi.json", localOnly(http.HandlerFunc(handleOpenAPISpec)))
}
