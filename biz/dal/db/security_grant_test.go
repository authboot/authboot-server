package db

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestSecurityGrantBindingsAndConcurrency(t *testing.T) {
	conn, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := conn.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := conn.AutoMigrate(&SecurityGrant{}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1234567890, 0)
	binding := SecurityGrant{Subject: "admin", AccountID: 1, OrganizationID: 2, SessionID: "session", Scope: "organization:delete"}
	token, err := NewSecurityGrant(conn, binding, now, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*SecurityGrant){
		func(g *SecurityGrant) { g.Subject = "user" },
		func(g *SecurityGrant) { g.AccountID = 2 },
		func(g *SecurityGrant) { g.OrganizationID = 3 },
		func(g *SecurityGrant) { g.SessionID = "other" },
		func(g *SecurityGrant) { g.Scope = "mfa:disable" },
	} {
		wrong := binding
		mutate(&wrong)
		if ConsumeSecurityGrant(conn, token, wrong, now) == nil {
			t.Fatal("foreign binding accepted")
		}
	}
	var count atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ConsumeSecurityGrant(conn, token, binding, now) == nil {
				count.Add(1)
			}
		}()
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatalf("accepted %d consumers", count.Load())
	}
	token, err = NewSecurityGrant(conn, binding, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ConsumeSecurityGrant(conn, token, binding, now.Add(time.Minute)) == nil {
		t.Fatal("expiry accepted")
	}
	var row SecurityGrant
	if err := conn.First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Hash == token {
		t.Fatal("plaintext token stored")
	}
}
