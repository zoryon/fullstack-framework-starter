package postgres

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PoolConfig struct {
	MaxConns          int32
	MinConns          int32
	MaxConnIdleTime   time.Duration
	MaxConnLifetime   time.Duration
	MaxConnLifeJitter time.Duration
	HealthCheckPeriod time.Duration
	StatementTimeout  time.Duration
}

// NewPool creates a PostgreSQL connection pool used by repositories.
func NewPool(ctx context.Context, dsn string, pc PoolConfig) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}

	if pc.MaxConns > 0 {
		cfg.MaxConns = pc.MaxConns
	}
	if pc.MinConns > 0 {
		cfg.MinConns = pc.MinConns
	}
	if pc.MaxConnIdleTime > 0 {
		cfg.MaxConnIdleTime = pc.MaxConnIdleTime
	}
	if pc.MaxConnLifetime > 0 {
		cfg.MaxConnLifetime = pc.MaxConnLifetime
	}
	if pc.MaxConnLifeJitter > 0 {
		cfg.MaxConnLifetimeJitter = pc.MaxConnLifeJitter
	}
	if pc.HealthCheckPeriod > 0 {
		cfg.HealthCheckPeriod = pc.HealthCheckPeriod
	}
	if pc.StatementTimeout > 0 {
		cfg.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(pc.StatementTimeout.Milliseconds(), 10)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("new postgres pool: %w", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for {
		if err := pool.Ping(ctx); err == nil {
			break
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			pool.Close()
			return nil, fmt.Errorf("postgres ping: %w", lastErr)
		}
		time.Sleep(1 * time.Second)
	}
	return pool, nil
}
