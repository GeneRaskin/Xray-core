package inbound

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// helper to flush one key for a clean test
func flushKey(t *testing.T, key string) {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: os.Getenv("REDIS_ADDR")})
	_ = rdb.Del(context.Background(), key).Err()
}

func TestLimiter_AllowsUpToThreeIPsAndDeniesFourth(t *testing.T) {
	os.Setenv("XRAY_UID_IP_TTL_SECS", "5") // 5s TTL for faster test

	uid := "f9bf6745-95f2-4efd-8523-d6d7f2d0237c"
	key := "vless:uid:{" + uid + "}:ips"
	flushKey(t, key)

	ctx := context.Background()

	ok, err := checkAndUpdateIP(ctx, uid, "198.51.100.1")
	if err != nil || !ok {
		t.Fatalf("1st ip should allow, got ok=%v err=%v", ok, err)
	}
	ok, err = checkAndUpdateIP(ctx, uid, "198.51.100.2")
	if err != nil || !ok {
		t.Fatalf("2nd ip should allow, got ok=%v err=%v", ok, err)
	}
	ok, err = checkAndUpdateIP(ctx, uid, "198.51.100.3")
	if err != nil || !ok {
		t.Fatalf("3rd ip should allow, got ok=%v err=%v", ok, err)
	}
	ok, err = checkAndUpdateIP(ctx, uid, "198.51.100.4")
	if err != nil || ok {
		t.Fatalf("4th ip should DENY, got ok=%v err=%v", ok, err)
	}

	// Wait for TTL, then a new IP should be allowed again
	time.Sleep(6 * time.Second)
	ok, err = checkAndUpdateIP(ctx, uid, "198.51.100.4")
	if err != nil || !ok {
		t.Fatalf("after TTL, new ip should allow again, got ok=%v err=%v", ok, err)
	}
}