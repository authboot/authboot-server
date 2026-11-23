package redis

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authboot/authboot-server/pkg/geoip"
)

func TestBulkRevokeConcurrentRefresh(t *testing.T) {
	securityRedis(t)
	store := SessionStore{}
	current, err := store.Create("user", 1, 1, "current", "Current", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		target, err := store.Create("user", 1, 1, fmt.Sprint(i), "Target", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = store.Rotate("user", target.RefreshToken, time.Hour) }()
		go func() {
			defer wg.Done()
			if _, err := store.RevokeUserSelection(1, 1, current.SessionID, "others", ""); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		if _, err := store.Get("user", target.SessionID); err != ErrSessionNotFound {
			t.Fatal("bulk revoke lost to refresh", err)
		}
		if _, err := store.ByRefresh("user", current.RefreshToken); err != nil {
			t.Fatal("current revoked", err)
		}
	}
}

func TestActivityGateTTLAndSnapshot(t *testing.T) {
	server := securityRedis(t)
	store := SessionStore{}
	meta := LoginMetadata{IP: "127.0.0.1", Location: geoip.Unknown("non_public")}
	rec, err := store.Create("user", 1, 2, "phone", "Phone", time.Hour, meta)
	if err != nil {
		t.Fatal(err)
	}
	server.FastForward(time.Minute)
	ttl := server.TTL(sessionKey("user", rec.SessionID))
	var winners int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			touched, err := store.TouchUser(2, 1, rec.SessionID, "127.0.0.2")
			if err != nil {
				t.Error(err)
			}
			if touched != nil {
				atomic.AddInt32(&winners, 1)
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("touch winners: %d", winners)
	}
	if server.TTL(sessionKey("user", rec.SessionID)) != ttl || server.TTL(refreshKey("user", rec.RefreshToken)) != ttl {
		t.Fatal("touch extended TTL")
	}
	got, err := store.Get("user", rec.SessionID)
	if err != nil || got.IP != meta.IP || got.Location != meta.Location || got.LastActiveIP != "127.0.0.2" {
		t.Fatalf("snapshot: %+v %v", got, err)
	}
	server.FastForward(5 * time.Minute)
	if touched, err := store.TouchUser(999, 1, rec.SessionID, "127.0.0.3"); err != nil || touched != nil {
		t.Fatal("cross-org touch", err)
	}
	if touched, err := store.TouchUser(2, 1, rec.SessionID, "127.0.0.3"); err != nil || touched == nil {
		t.Fatal("gate failed to expire", err)
	}
}

func TestActivityRotateRevokeRace(t *testing.T) {
	securityRedis(t)
	store := SessionStore{}
	for i := 0; i < 30; i++ {
		rec, err := store.Create("user", 1, 2, "phone", "Phone", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := store.TouchUser(2, 1, rec.SessionID, "127.0.0.2"); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := store.Rotate("user", rec.RefreshToken, time.Hour); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		got, err := store.Get("user", rec.SessionID)
		if err != nil || got.LastActiveIP != "127.0.0.2" || got.RefreshToken == rec.RefreshToken {
			t.Fatal("rotate overwrote activity", err)
		}
		if _, err := store.ByRefresh("user", got.RefreshToken); err != nil {
			t.Fatal(err)
		}
		rdbSession.Del(sessionKey("user", rec.SessionID) + ":activity")
		wg.Add(3)
		go func() { defer wg.Done(); _, _ = store.TouchUser(2, 1, rec.SessionID, "127.0.0.3") }()
		go func() { defer wg.Done(); _, _ = store.Rotate("user", got.RefreshToken, time.Hour) }()
		go func() {
			defer wg.Done()
			if err := store.Revoke("user", rec.SessionID); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		if _, err := store.Get("user", rec.SessionID); err != ErrSessionNotFound {
			t.Fatal("revoked session resurrected", err)
		}
	}
}

func TestScopedBulkRevokePreservesCurrentAndAllDeviceSessions(t *testing.T) {
	securityRedis(t)
	store := SessionStore{}
	create := func(user, org int64, device string) *SessionRecord {
		r, e := store.Create("user", user, org, device, device, time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	current := create(1, 1, "current")
	a, b := create(1, 1, "other"), create(1, 1, "other")
	crossOrg, crossUser := create(1, 2, "other"), create(2, 1, "other")
	if _, err := store.RevokeUserSelection(1, 2, current.SessionID, "others", ""); err == nil {
		t.Fatal("owner bypass")
	}
	ids, err := store.RevokeUserSelection(1, 1, current.SessionID, "device", "other")
	if err != nil || len(ids) != 2 {
		t.Fatalf("%v %v", ids, err)
	}
	for _, r := range []*SessionRecord{a, b} {
		if _, e := store.ByRefresh("user", r.RefreshToken); e != ErrSessionNotFound {
			t.Fatal("device session survived", e)
		}
	}
	create(1, 1, "third")
	ids, err = store.RevokeUserSelection(1, 1, current.SessionID, "others", "")
	if err != nil || len(ids) != 1 {
		t.Fatalf("%v %v", ids, err)
	}
	for _, r := range []*SessionRecord{current, crossOrg, crossUser} {
		if _, e := store.ByRefresh("user", r.RefreshToken); e != nil {
			t.Fatal("wrong session revoked", e)
		}
	}
}
