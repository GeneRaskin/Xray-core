package inbound

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	redisOnce  sync.Once
	rdb        *redis.Client
	maxIPs     = 3
	defaultTTL = 180 * time.Second
)

var allowIPScript = redis.NewScript(`
-- ACTIVE set:
-- KEYS[1] = vless:uid:{UID}:ips        (ZSET: member=ip, score=last_seen)
-- INPUT:
-- ARGV[1] = ip
-- ARGV[2] = ttl_seconds   (activity window)
-- ARGV[3] = max_ips
local key_active = KEYS[1]
local ip  = ARGV[1]
local ttl = tonumber(ARGV[2])
local max = tonumber(ARGV[3])

-- Derive UID from active-key (vless:uid:{...}:ips)
local uid = string.match(key_active, "vless:uid:{(.-)}:ips")
if not uid then uid = "unknown" end

-- Time
local t   = redis.call('TIME')
local now = tonumber(t[1])

-- METRIC KEYS (no TTL for counters)
local k_allow   = "vless:uid:{"..uid.."}:metrics:admit_allow_total"           -- STRING (counter)
local k_deny    = "vless:uid:{"..uid.."}:metrics:admit_deny_total"            -- STRING (counter)
local k_deny_ipq= "vless:uid:{"..uid.."}:metrics:deny_reason:ip_quota"        -- STRING (counter)

-- 1) Purge stale entries in ACTIVE (windowed limiter)
redis.call('ZREMRANGEBYSCORE', key_active, '-inf', now - ttl)

-- Helper: record "allow" metrics
local function on_allow()
  redis.call('INCR', k_allow)
end

-- 2) If IP already present -> refresh + allow
if redis.call('ZSCORE', key_active, ip) then
  redis.call('ZADD', key_active, now, ip)
  redis.call('EXPIRE', key_active, ttl * 2)
  on_allow()
  return 1
end

-- 3) New IP: enforce cap
local count = redis.call('ZCARD', key_active)
if count < max then
  redis.call('ZADD', key_active, now, ip)
  redis.call('EXPIRE', key_active, ttl * 2)
  on_allow()
  return 1
end

-- 4) DENY
redis.call('INCR', k_deny)
redis.call('INCR', k_deny_ipq)
return 0
`)

func atoiEnv(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

func initRedis() {
	redisOnce.Do(func() {
		// TTL and max IPs can still be overridden
		if ttl := atoiEnv("XRAY_UID_IP_TTL_SECS", 0); ttl > 0 {
			defaultTTL = time.Duration(ttl) * time.Second
		}
		if m := atoiEnv("XRAY_UID_MAX_IPS", 0); m > 0 {
			maxIPs = m
		}

		addr := os.Getenv("REDIS_ADDR")
		if addr == "" {
			// default for K8s cluster
			addr = "redis.default.svc.cluster.local:6379"
		}

		rdb = redis.NewClient(&redis.Options{
			Addr: addr,
			DB:   0,
		})
	})
}

func checkAndUpdateIP(ctx context.Context, uid, ip string) (bool, error) {
	initRedis()
	if rdb == nil {
		return true, nil
	}
	key := "vless:uid:{" + uid + "}:ips"
	return allowIPScript.Run(ctx, rdb, []string{key}, ip, int64(defaultTTL/time.Second), maxIPs).Bool()
}
