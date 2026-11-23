package redis

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/authboot/authboot-server/pkg/geoip"
	goredis "github.com/go-redis/redis/v7"
)

func TestSessionMetadataRoundTripAndRotate(t *testing.T) {
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	old := rdbSession
	rdbSession = client
	t.Cleanup(func() { rdbSession = old; _ = client.Close() })
	store := SessionStore{}
	meta := LoginMetadata{IP: "8.8.8.8", UserAgent: "test", ClientID: 12, Location: geoip.Location{CountryCode: "US", Country: "美国", Source: "geolite2", Status: "approximate"}}
	rec, err := store.Create("user", 42, 1, "device", "phone", time.Hour, meta)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("user", rec.SessionID)
	if err != nil || got.LoginMetadata != meta {
		t.Fatalf("%+v %v", got, err)
	}
	rotated, err := store.Rotate("user", rec.RefreshToken, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.LoginMetadata != meta || rotated.CreatedAt != rec.CreatedAt || rotated.SessionID != rec.SessionID || rotated.RefreshToken == rec.RefreshToken {
		t.Fatalf("%+v", rotated)
	}
	got, err = store.Get("user", rec.SessionID)
	if err != nil || got.LoginMetadata != meta {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err = store.Rotate("user", rec.RefreshToken, time.Hour); err != ErrSessionNotFound {
		t.Fatal(err)
	}
	if _, err = store.Get("admin", rec.SessionID); err != ErrSessionNotFound {
		t.Fatal(err)
	}

	// An actual pre-feature JSON record, not a serialization of the new type.
	_ = client.Set(sessionKey("user", "old"), `{"session_id":"old","account_id":42,"organization_id":1,"refresh_token":"old-token","created_at":123,"expires_at":9999999999}`, time.Hour).Err()
	_ = client.Set(refreshKey("user", "old-token"), "old", time.Hour).Err()
	legacy, err := store.Rotate("user", "old-token", time.Hour)
	if err != nil || legacy.IP != "" || legacy.Location.Status != "" || legacy.CreatedAt != 123 {
		t.Fatalf("%+v %v", legacy, err)
	}
}
