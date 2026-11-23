package db

import (
	"fmt"
	"sync"
	"testing"

	"github.com/authboot/authboot-server/pkg/geoip"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestSecurityLoginIdempotencyAndGeography(t *testing.T) {
	conn, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := conn.DB()
	sqlDB.SetMaxOpenConns(1)
	old := DB
	DB = conn
	t.Cleanup(func() { DB = old; _ = sqlDB.Close() })
	if err := conn.AutoMigrate(&User{}, &UserDevice{}, &UserSecurityEvent{}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Create(&User{ID: 1, OrganizationID: 1, Status: 1}).Error; err != nil {
		t.Fatal(err)
	}
	known := func(country string) geoip.Location {
		return geoip.Location{CountryCode: country, Status: "approximate"}
	}
	login := func(device, sid string, loc geoip.Location) (*UserSecurityEvent, error) {
		return RecordSecurityLogin(&UserDevice{OrganizationID: 1, UserID: 1, DeviceID: device, CreatedAt: 1, LastUsedAt: 1, LastLocation: loc}, sid)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := login("same", fmt.Sprint(i), known("CN")); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	var count int64
	conn.Model(&UserSecurityEvent{}).Count(&count)
	if count != 1 {
		t.Fatalf("duplicate first-device events: %d", count)
	}
	conn.Model(&UserDevice{}).Count(&count)
	if count != 1 {
		t.Fatal("duplicate devices", count)
	}
	event, err := login("same", "country", known("US"))
	if err != nil || event == nil || event.Kind != "country_changed" {
		t.Fatalf("%+v %v", event, err)
	}
	if event, err := login("same", "unknown", geoip.Unknown("unavailable")); err != nil || event != nil {
		t.Fatal("unknown falsely flagged", event, err)
	}
	if event, err := login("", "missing-device", geoip.Unknown("non_public")); err != nil || event != nil {
		t.Fatal("missing device trusted", event, err)
	}
	if CountryChanged(known("CN"), geoip.Unknown("not_found")) || CountryChanged(geoip.Location{CountryCode: "CN"}, known("US")) || CountryChanged(known("CN"), known("CN")) {
		t.Fatal("unreliable geography flagged")
	}
	if _, err := RecordSecurityLogin(&UserDevice{OrganizationID: 2, UserID: 1, DeviceID: "same"}, "wrong-org"); err == nil {
		t.Fatal("cross-org registration")
	}
}
