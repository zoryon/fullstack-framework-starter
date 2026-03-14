package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"nutrico/server/internal/platform/response"

	goredis "github.com/redis/go-redis/v9"
)

// IPRateLimiter is a lightweight in-memory per-IP limiter for sensitive auth endpoints.
type IPRateLimiter struct {
	redis    *goredis.Client
	prefix   string
	rlScript *goredis.Script

	shards [64]rateLimitShard
}

type rlEntry struct {
	tokens     int
	resetAt    time.Time
	violations int
}

type rateLimitShard struct {
	mu      sync.Mutex
	entries map[string]*rlEntry
}

const rlEntryTTL = 15 * time.Minute

const defaultRateLimitPrefix = "nutrico:rl"

const redisRateLimitScript = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
if current <= tonumber(ARGV[2]) then
  return 1
end
return 0
`

func NewIPRateLimiter(redisClient *goredis.Client) *IPRateLimiter {
	l := &IPRateLimiter{}
	l.redis = redisClient
	l.prefix = defaultRateLimitPrefix
	l.rlScript = goredis.NewScript(redisRateLimitScript)
	for i := range l.shards {
		l.shards[i].entries = make(map[string]*rlEntry)
	}
	go l.cleanupLoop()
	return l
}

func (l *IPRateLimiter) Limit(max int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bucket := r.Method + ":" + r.URL.Path + ":" + strconv.Itoa(max) + ":" + window.String()
			ip := clientIP(r)
			if !l.allow(r.Context(), bucket, ip, max, window) {
				response.Error(w, http.StatusTooManyRequests, "rate_limited")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (l *IPRateLimiter) allow(ctx context.Context, bucket, ip string, max int, window time.Duration) bool {
	if l.redis != nil {
		ok, err := l.allowRedis(ctx, bucket, ip, max, window)
		if err == nil {
			return ok
		}
	}

	return l.allowLocal(bucket+"|"+ip, max, window)
}

func (l *IPRateLimiter) allowRedis(ctx context.Context, bucket, ip string, max int, window time.Duration) (bool, error) {
	if window <= 0 {
		window = time.Minute
	}
	if max <= 0 {
		max = 1
	}

	key := fmt.Sprintf("%s:%s:%s", l.prefix, bucket, ip)
	res, err := l.rlScript.Run(ctx, l.redis, []string{key}, window.Milliseconds(), max).Int()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

func (l *IPRateLimiter) allowLocal(key string, max int, window time.Duration) bool {
	now := time.Now().UTC()
	sh := l.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e, ok := sh.entries[key]
	if !ok || now.After(e.resetAt) {
		sh.entries[key] = &rlEntry{tokens: max - 1, resetAt: now.Add(window)}
		return true
	}

	if e.tokens <= 0 {
		e.violations++
		return false
	}
	e.tokens--
	return true
}

func (l *IPRateLimiter) shard(ip string) *rateLimitShard {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(ip); i++ {
		h ^= uint64(ip[i])
		h *= 1099511628211
	}
	idx := int(h % uint64(len(l.shards)))
	return &l.shards[idx]
}

func (l *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for now := range ticker.C {
		cutoff := now.UTC().Add(-rlEntryTTL)
		for i := range l.shards {
			sh := &l.shards[i]
			sh.mu.Lock()
			for ip, e := range sh.entries {
				if e.resetAt.Before(cutoff) {
					delete(sh.entries, ip)
				}
			}
			sh.mu.Unlock()
		}
	}
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if first != "" {
			return first
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return h
	}
	return r.RemoteAddr
}
