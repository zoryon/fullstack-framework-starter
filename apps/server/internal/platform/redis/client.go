package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

type ClientConfig struct {
	PoolSize        int
	MinIdleConns    int
	PoolTimeout     time.Duration
	ConnMaxIdleTime time.Duration
	ConnMaxLifetime time.Duration
}

// NewClient returns a Redis client used by auth/session stores.
func NewClient(ctx context.Context, addr, password string, db int, rc ClientConfig) (*goredis.Client, error) {
	cli := goredis.NewClient(&goredis.Options{
		Addr:         addr,
		Password:     password,
		DB:           db,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		MaxRetries:      2,
		MinRetryBackoff: 10 * time.Millisecond,
		MaxRetryBackoff: 200 * time.Millisecond,
		PoolSize:        rc.PoolSize,
		MinIdleConns:    rc.MinIdleConns,
		PoolTimeout:     rc.PoolTimeout,
		ConnMaxIdleTime: rc.ConnMaxIdleTime,
		ConnMaxLifetime: rc.ConnMaxLifetime,
	})

	if err := cli.Ping(ctx).Err(); err != nil {
		_ = cli.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}

	return cli, nil
}
