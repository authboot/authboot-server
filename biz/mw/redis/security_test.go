package redis

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/go-redis/redis/v7"
)

func securityRedis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	oldSession, oldCode := rdbSession, rdbCode
	rdbSession, rdbCode = client, client
	t.Cleanup(func() { rdbSession, rdbCode = oldSession, oldCode; _ = client.Close() })
	return server
}

func TestConcurrentRefreshSingleWinnerAndReplay(t *testing.T) {
	securityRedis(t)
	store := SessionStore{}
	rec, err := store.Create("user", 1, 2, "", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var winners int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Rotate("user", rec.RefreshToken, time.Hour); err == nil {
				atomic.AddInt32(&winners, 1)
			} else if err != ErrSessionNotFound {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("winners = %d", winners)
	}
	current, err := store.Get("user", rec.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rotate("user", rec.RefreshToken, time.Hour); err != ErrSessionNotFound {
		t.Fatal(err)
	}
	if err := store.RevokeByRefresh("user", rec.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rotate("user", current.RefreshToken, time.Hour); err != nil {
		t.Fatal("replay killed winner:", err)
	}
}

func TestRevokeRefreshNeverResurrects(t *testing.T) {
	securityRedis(t)
	store := SessionStore{}
	for i := 0; i < 30; i++ {
		rec, err := store.Create("user", 1, 2, "", "", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = store.Rotate("user", rec.RefreshToken, time.Hour) }()
		go func() {
			defer wg.Done()
			if err := store.Revoke("user", rec.SessionID); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		if _, err := store.Get("user", rec.SessionID); err != ErrSessionNotFound {
			t.Fatalf("resurrected: %v", err)
		}
	}
}

func TestCodeSingleConsumptionFailureBudgetAndRate(t *testing.T) {
	server := securityRedis(t)
	store := Code{}
	if err := store.Store("login", "account", "123456", time.Minute); err != nil {
		t.Fatal(err)
	}
	var winners int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.Verify("login", "account", "123456") {
				atomic.AddInt32(&winners, 1)
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("consumed %d times", winners)
	}
	_ = store.Store("login", "account", "123456", time.Minute)
	for i := 0; i < 5; i++ {
		if store.Verify("login", "account", "bad") {
			t.Fatal("accepted wrong code")
		}
	}
	if store.Verify("login", "account", "123456") {
		t.Fatal("failure budget bypass")
	}
	_ = store.Store("login", "account", "new", time.Minute)
	store.Discard("login", "account", "old")
	if !store.Verify("login", "account", "new") {
		t.Fatal("discard deleted replacement")
	}
	winners = 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.Allow("ip", 3, time.Minute) {
				atomic.AddInt32(&winners, 1)
			}
		}()
	}
	wg.Wait()
	if winners != 3 {
		t.Fatalf("rate allowed %d", winners)
	}
	server.FastForward(time.Minute)
	if !store.Allow("ip", 3, time.Minute) {
		t.Fatal("rate did not expire")
	}
	_ = store.Store("captcha_grant", "token", "login:ip1", time.Minute)
	if store.Verify("captcha_grant", "token", "register:ip1") || store.Verify("captcha_grant", "token", "login:ip2") {
		t.Fatal("binding bypass")
	}
	if !store.Verify("captcha_grant", "token", "login:ip1") || store.Verify("captcha_grant", "token", "login:ip1") {
		t.Fatal("grant consumption")
	}
}

func TestFailedRotateKeepsValidOldToken(t *testing.T) {
	securityRedis(t)
	store := SessionStore{}
	rec, err := store.Create("user", 1, 2, "", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Redis Lua does not roll back runtime errors. Detect corrupt index types
	// before making any session/token mutation.
	rdbSession.Set(userSessionsKey("user", 1), "wrong-type", time.Hour)
	if _, err := store.Rotate("user", rec.RefreshToken, time.Hour); err == nil {
		t.Fatal("accepted invalid index")
	}
	if _, err := store.ByRefresh("user", rec.RefreshToken); err != nil {
		t.Fatal("failed rotation consumed old token", err)
	}
}
