package session

import (
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/geoip"
	"testing"
)

func TestSessionLocationMapping(t *testing.T) {
	rec := &redis.SessionRecord{SessionID: "sid", AccountID: 4, OrganizationID: 5, CreatedAt: 123, ExpiresAt: 456, LoginMetadata: redis.LoginMetadata{IP: "1.2.3.4", ClientID: 7, Location: geoip.Location{CountryCode: "CN", Country: "中国", Region: "广东省", City: "深圳市", Display: "中国 · 广东省 · 深圳市（IP 近似位置）", Source: "ip2region", Status: "approximate"}}}
	got := toSessionProto(rec)
	if got.Ip != rec.IP || got.ClientId != 7 || got.Location.City != "深圳市" || got.Location.Source != "ip2region" || got.SessionId != "sid" || got.ExpiresAt != 456 {
		t.Fatalf("%+v", got)
	}
	legacy := toSessionProto(&redis.SessionRecord{SessionID: "old"})
	if legacy.Location.Status != "unknown" || legacy.Location.Display != "未知地区" || legacy.Ip != "" {
		t.Fatal(legacy)
	}
}
