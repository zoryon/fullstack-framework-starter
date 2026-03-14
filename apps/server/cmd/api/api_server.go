package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	domainauth "nutrico/server/internal/domain/auth"
	handlerauth "nutrico/server/internal/handler/auth"
	"nutrico/server/internal/middleware"
	"nutrico/server/internal/platform/config"
	platformemail "nutrico/server/internal/platform/email"
	"nutrico/server/internal/platform/postgres"
	platformredis "nutrico/server/internal/platform/redis"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func runAPI() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx := context.Background()
	pg, err := postgres.NewPool(ctx, cfg.PostgresDSN, postgres.PoolConfig{
		MaxConns:          cfg.PostgresMaxConns,
		MinConns:          cfg.PostgresMinConns,
		MaxConnIdleTime:   cfg.PostgresMaxConnIdleTime,
		MaxConnLifetime:   cfg.PostgresMaxConnLifetime,
		MaxConnLifeJitter: cfg.PostgresConnMaxJitter,
		HealthCheckPeriod: cfg.PostgresHealthCheckPeriod,
		StatementTimeout:  cfg.PostgresStatementTimeout,
	})
	if err != nil {
		return err
	}
	defer pg.Close()

	rdb, err := platformredis.NewClient(ctx, cfg.RedisAddr, cfg.RedisPass, cfg.RedisDB, platformredis.ClientConfig{
		PoolSize:        cfg.RedisPoolSize,
		MinIdleConns:    cfg.RedisMinIdleConns,
		PoolTimeout:     cfg.RedisPoolTimeout,
		ConnMaxIdleTime: cfg.RedisConnMaxIdleTime,
		ConnMaxLifetime: cfg.RedisConnMaxLifetime,
	})
	if err != nil {
		return err
	}
	defer rdb.Close()

	repo := domainauth.NewRepository(pg)
	store := domainauth.NewSessionStore(rdb)
	jwtm := domainauth.NewJWTManager(cfg.JWTSecret, cfg.AccessTokenTTL)

	var mailer domainauth.Mailer
	if smtpSender, smtpErr := platformemail.NewSMTPSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPFrom); smtpErr != nil {
		log.Printf("smtp mailer disabled: %v", smtpErr)
	} else {
		mailer = smtpSender
	}

	svc := domainauth.NewService(repo, store, jwtm, mailer, domainauth.ServiceConfig{
		BaseURL:            cfg.BaseURL,
		AccessTokenTTL:     cfg.AccessTokenTTL,
		RefreshTokenTTL:    cfg.RefreshTokenTTL,
		SessionTTL:         cfg.SessionTTL,
		SessionAbsoluteTTL: cfg.SessionAbsoluteTTL,
		EmailVerifyTTL:     cfg.EmailVerifyTTL,
		MagicLinkTTL:       cfg.MagicLinkTTL,
		PasswordResetTTL:   cfg.PasswordResetTTL,
	})

	authH := handlerauth.NewHandler(svc, cfg.CookieSec, handlerauth.GoogleOAuthConfig{
		Enabled:      cfg.GoogleOAuthEnabled,
		ClientID:     cfg.GoogleOAuthClientID,
		ClientSecret: cfg.GoogleOAuthClientSecret,
		RedirectURL:  cfg.GoogleOAuthRedirectURL,
		AuthURL:      cfg.GoogleOAuthAuthURL,
		TokenURL:     cfg.GoogleOAuthTokenURL,
		UserInfoURL:  cfg.GoogleOAuthUserInfoURL,
	}, cfg.JWTSecret)
	authMW := middleware.AuthMiddleware{Service: svc}
	rl := middleware.NewIPRateLimiter(rdb)

	mux := http.NewServeMux()
	if cfg.MetricsEnabled {
		mux.Handle(cfg.MetricsPath, promhttp.Handler())
		log.Printf("metrics enabled on %s", cfg.MetricsPath)
	}

	registerAPIRoutes(mux, cfg, pg, rdb, authH, authMW, rl)

	handler := recoverPanic(withMaxInFlight(cfg.HTTPMaxInFlight, withRequestTimeout(cfg.HTTPRequestTimeout, mux)))
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
		MaxHeaderBytes:    cfg.HTTPMaxHeaderBytes,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	ctxSig, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctxSig.Done():
		log.Printf("api received shutdown signal")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTPShutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
