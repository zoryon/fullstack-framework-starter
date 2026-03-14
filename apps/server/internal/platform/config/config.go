package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config contains runtime settings for auth and API wiring.
type Config struct {
	HTTPAddr string
	BaseURL  string

	HTTPReadHeaderTimeout time.Duration
	HTTPReadTimeout       time.Duration
	HTTPWriteTimeout      time.Duration
	HTTPIdleTimeout       time.Duration
	HTTPMaxHeaderBytes    int
	HTTPRequestTimeout    time.Duration
	HTTPShutdownTimeout   time.Duration
	HTTPMaxInFlight       int
	ReadyCheckTimeout     time.Duration
	MetricsEnabled        bool
	MetricsPath           string

	PostgresDSN string
	RedisAddr   string
	RedisPass   string
	RedisDB     int

	PostgresMaxConns        int32
	PostgresMinConns        int32
	PostgresMaxConnIdleTime time.Duration
	PostgresMaxConnLifetime time.Duration
	PostgresConnMaxJitter   time.Duration
	PostgresHealthCheckPeriod time.Duration
	PostgresStatementTimeout  time.Duration

	RedisPoolSize        int
	RedisMinIdleConns    int
	RedisPoolTimeout     time.Duration
	RedisConnMaxIdleTime time.Duration
	RedisConnMaxLifetime time.Duration

	JWTSecret string
	CookieSec bool

	GoogleOAuthClientID     string
	GoogleOAuthClientSecret string
	GoogleOAuthRedirectURL  string
	GoogleOAuthAuthURL      string
	GoogleOAuthTokenURL     string
	GoogleOAuthUserInfoURL  string
	GoogleOAuthEnabled      bool

	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string
	SMTPFrom string

	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	SessionTTL          time.Duration
	SessionAbsoluteTTL  time.Duration
	EmailVerifyTTL      time.Duration
	MagicLinkTTL        time.Duration
	PasswordResetTTL    time.Duration
}

func Load() (Config, error) {
	postgresDSN := getEnvAny([]string{"POSTGRES_DSN", "DATABASE_URL"}, "")
	if postgresDSN == "" {
		postgresUser := getEnv("POSTGRES_APP_DB_USER", "postgres")
		postgresPass := getEnv("POSTGRES_APP_DB_PASSWORD", "postgres")
		postgresHost := getEnv("POSTGRES_HOST", "postgres")
		postgresPort := getEnv("POSTGRES_PORT", "5432")
		postgresDB := getEnv("POSTGRES_DB", "nutrico")
		postgresSSLMode := getEnv("POSTGRES_SSLMODE", "disable")

		postgresDSN = fmt.Sprintf(
			"postgres://%s:%s@%s:%s/%s?sslmode=%s",
			url.QueryEscape(postgresUser),
			url.QueryEscape(postgresPass),
			postgresHost,
			postgresPort,
			postgresDB,
			postgresSSLMode,
		)
	}

	cfg := Config{
		HTTPAddr:            getEnv("HTTP_ADDR", ":8080"),
		BaseURL:             getEnv("BASE_URL", "http://localhost"),
		HTTPReadHeaderTimeout: mustDuration("HTTP_READ_HEADER_TIMEOUT", "5s"),
		HTTPReadTimeout:       mustDuration("HTTP_READ_TIMEOUT", "15s"),
		HTTPWriteTimeout:      mustDuration("HTTP_WRITE_TIMEOUT", "30s"),
		HTTPIdleTimeout:       mustDuration("HTTP_IDLE_TIMEOUT", "60s"),
		HTTPMaxHeaderBytes:    mustInt("HTTP_MAX_HEADER_BYTES", 1<<20),
		HTTPRequestTimeout:    mustDuration("HTTP_REQUEST_TIMEOUT", "30s"),
		HTTPShutdownTimeout:   mustDuration("HTTP_SHUTDOWN_TIMEOUT", "20s"),
		HTTPMaxInFlight:       mustInt("HTTP_MAX_IN_FLIGHT", 20000),
		ReadyCheckTimeout:     mustDuration("READY_CHECK_TIMEOUT", "2s"),
		MetricsEnabled:        getEnv("METRICS_ENABLED", "false") == "true",
		MetricsPath:           getEnv("METRICS_PATH", "/metrics"),
		PostgresDSN:         postgresDSN,
		RedisAddr:           getEnvAny([]string{"REDIS_ADDR"}, "localhost:6379"),
		RedisPass:           getEnvAny([]string{"REDIS_PASSWORD"}, ""),
		PostgresMaxConns:        int32(mustInt("POSTGRES_MAX_CONNS", 80)),
		PostgresMinConns:        int32(mustInt("POSTGRES_MIN_CONNS", 8)),
		PostgresMaxConnIdleTime: mustDuration("POSTGRES_MAX_CONN_IDLE_TIME", "5m"),
		PostgresMaxConnLifetime: mustDuration("POSTGRES_MAX_CONN_LIFETIME", "45m"),
		PostgresConnMaxJitter:   mustDuration("POSTGRES_MAX_CONN_LIFETIME_JITTER", "2m"),
		PostgresHealthCheckPeriod: mustDuration("POSTGRES_HEALTHCHECK_PERIOD", "30s"),
		PostgresStatementTimeout:  mustDuration("POSTGRES_STATEMENT_TIMEOUT", "8s"),
		RedisPoolSize:           mustInt("REDIS_POOL_SIZE", 100),
		RedisMinIdleConns:       mustInt("REDIS_MIN_IDLE_CONNS", 10),
		RedisPoolTimeout:        mustDuration("REDIS_POOL_TIMEOUT", "4s"),
		RedisConnMaxIdleTime:    mustDuration("REDIS_CONN_MAX_IDLE_TIME", "10m"),
		RedisConnMaxLifetime:    mustDuration("REDIS_CONN_MAX_LIFETIME", "1h"),
		JWTSecret:           getEnv("JWT_SECRET", ""),
		CookieSec:           getEnv("COOKIE_SECURE", "false") == "true",
		GoogleOAuthClientID:     getEnvAny([]string{"GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_CLIENT_ID"}, ""),
		GoogleOAuthClientSecret: getEnvAny([]string{"GOOGLE_OAUTH_CLIENT_SECRET", "GOOGLE_CLIENT_SECRET"}, ""),
		GoogleOAuthRedirectURL:  getEnvAny([]string{"GOOGLE_OAUTH_REDIRECT_URL", "GOOGLE_REDIRECT_URL"}, ""),
		GoogleOAuthAuthURL:      getEnv("GOOGLE_OAUTH_AUTH_URL", "https://accounts.google.com/o/oauth2/v2/auth"),
		GoogleOAuthTokenURL:     getEnv("GOOGLE_OAUTH_TOKEN_URL", "https://oauth2.googleapis.com/token"),
		GoogleOAuthUserInfoURL:  getEnv("GOOGLE_OAUTH_USERINFO_URL", "https://openidconnect.googleapis.com/v1/userinfo"),
		SMTPHost:                getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPUser:                getEnv("SMTP_USER", ""),
		SMTPPass:                getEnv("SMTP_PASS", ""),
		SMTPFrom:                getEnv("SMTP_FROM", ""),
		AccessTokenTTL:      mustDuration("ACCESS_TOKEN_TTL", "15m"),
		RefreshTokenTTL:     mustDuration("REFRESH_TOKEN_TTL", "720h"),
		SessionTTL:          mustDuration("SESSION_TTL", "15m"),
		SessionAbsoluteTTL:  mustDuration("SESSION_ABSOLUTE_TTL", "24h"),
		EmailVerifyTTL:      mustDuration("EMAIL_VERIFY_TTL", "24h"),
		MagicLinkTTL:        mustDuration("MAGIC_LINK_TTL", "15m"),
		PasswordResetTTL:    mustDuration("PASSWORD_RESET_TTL", "1h"),
	}

	if redisURL := getEnvAny([]string{"REDIS_CACHE_URL", "REDIS_URL"}, ""); redisURL != "" {
		if addr, pass, db, err := parseRedisURL(redisURL); err == nil {
			cfg.RedisAddr = addr
			cfg.RedisPass = pass
			cfg.RedisDB = db
		}
	}

	if cfg.JWTSecret == "" {
		return Config{}, fmt.Errorf("missing JWT_SECRET")
	}

	redisDB, err := strconv.Atoi(getEnv("REDIS_DB", strconv.Itoa(cfg.RedisDB)))
	if err != nil {
		return Config{}, fmt.Errorf("invalid REDIS_DB: %w", err)
	}
	cfg.RedisDB = redisDB

	smtpPort, err := strconv.Atoi(getEnv("SMTP_PORT", "587"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid SMTP_PORT: %w", err)
	}
	cfg.SMTPPort = smtpPort

	cfg.GoogleOAuthEnabled = cfg.GoogleOAuthClientID != "" &&
		cfg.GoogleOAuthClientSecret != "" &&
		cfg.GoogleOAuthRedirectURL != ""

	if err := validate(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func validate(cfg Config) error {
	if cfg.HTTPMaxHeaderBytes <= 0 {
		return fmt.Errorf("HTTP_MAX_HEADER_BYTES must be > 0")
	}
	if cfg.HTTPMaxInFlight <= 0 {
		return fmt.Errorf("HTTP_MAX_IN_FLIGHT must be > 0")
	}
	if cfg.HTTPRequestTimeout <= 0 {
		return fmt.Errorf("HTTP_REQUEST_TIMEOUT must be > 0")
	}
	if cfg.HTTPShutdownTimeout <= 0 {
		return fmt.Errorf("HTTP_SHUTDOWN_TIMEOUT must be > 0")
	}
	if !strings.HasPrefix(cfg.MetricsPath, "/") {
		return fmt.Errorf("METRICS_PATH must start with '/'")
	}
	if cfg.PostgresMaxConns <= 0 {
		return fmt.Errorf("POSTGRES_MAX_CONNS must be > 0")
	}
	if cfg.PostgresMinConns < 0 {
		return fmt.Errorf("POSTGRES_MIN_CONNS must be >= 0")
	}
	if cfg.PostgresMinConns > cfg.PostgresMaxConns {
		return fmt.Errorf("POSTGRES_MIN_CONNS cannot exceed POSTGRES_MAX_CONNS")
	}
	if cfg.RedisPoolSize <= 0 {
		return fmt.Errorf("REDIS_POOL_SIZE must be > 0")
	}
	if cfg.RedisMinIdleConns < 0 {
		return fmt.Errorf("REDIS_MIN_IDLE_CONNS must be >= 0")
	}
	return nil
}

func getEnv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func getEnvAny(keys []string, fallback string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return fallback
}

func parseRedisURL(raw string) (addr, password string, db int, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", 0, err
	}

	addr = u.Host
	if addr == "" {
		return "", "", 0, fmt.Errorf("missing host in redis url")
	}

	if u.User != nil {
		if p, ok := u.User.Password(); ok {
			password = p
		}
	}

	db = 0
	if path := strings.TrimPrefix(u.Path, "/"); path != "" {
		n, convErr := strconv.Atoi(path)
		if convErr != nil {
			return "", "", 0, convErr
		}
		db = n
	}

	return addr, password, db, nil
}

func mustDuration(key, fallback string) time.Duration {
	v := getEnv(key, fallback)
	d, err := time.ParseDuration(v)
	if err != nil {
		d, _ = time.ParseDuration(fallback)
	}
	return d
}

func mustInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
