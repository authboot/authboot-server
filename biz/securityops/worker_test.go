package securityops

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestDeviceRetentionCursorSkipsActiveAndWraps(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		t.Run(fmt.Sprintf("dry_run=%t", dryRun), func(t *testing.T) {
			w := testWorker(t)
			w.Config.Batch, w.Config.DryRun = 2, dryRun
			r := miniredis.RunT(t)
			t.Setenv("REDIS_ADDR", r.Addr())
			t.Setenv("REDIS_PASSWORD", "")
			redis.InitRedis()
			now := time.Now()
			old := now.Add(-365 * 24 * time.Hour).Unix()
			for _, owner := range []any{&db.AdminUser{ID: 1}, &db.User{ID: 1, OrganizationID: 1}} {
				if err := w.DB.Create(owner).Error; err != nil {
					t.Fatal(err)
				}
			}
			tables := map[string]string{"admin": (db.AdminDevice{}).TableName(), "user": (db.UserDevice{}).TableName()}
			var sessions []struct{ subject, sid string }
			for _, subject := range []string{"admin", "user"} {
				for i := 1; i <= w.Config.Batch+1; i++ {
					device := fmt.Sprintf("device-%d", i)
					var row any
					if subject == "admin" {
						// Disjoint ID ranges catch accidentally shared cursors.
						row = &db.AdminDevice{ID: int64(100 + i), AccountID: 1, DeviceID: device, LastUsedAt: old}
					} else {
						row = &db.UserDevice{ID: int64(i), UserID: 1, OrganizationID: 1, DeviceID: device, LastUsedAt: old, LastActiveAt: old}
					}
					if err := w.DB.Create(row).Error; err != nil {
						t.Fatal(err)
					}
					if i <= w.Config.Batch {
						rec, err := (redis.SessionStore{}).Create(subject, 1, 1, device, "", time.Hour)
						if err != nil {
							t.Fatal(err)
						}
						sessions = append(sessions, struct{ subject, sid string }{subject, rec.SessionID})
					}
				}
			}
			count := func(want int64) {
				t.Helper()
				for subject, table := range tables {
					var n int64
					if err := w.DB.Table(table).Count(&n).Error; err != nil || n != want {
						t.Fatalf("%s: count=%d want=%d err=%v", subject, n, want, err)
					}
				}
			}
			run := func() {
				t.Helper()
				if _, err := w.RunRetention(context.Background(), now); err != nil {
					t.Fatal(err)
				}
			}
			run() // First page is entirely active; no deletion, but both advance.
			count(3)
			if w.deviceCursors["admin"] != 102 || w.deviceCursors["user"] != 2 {
				t.Fatal("skipped active devices did not advance independent cursors", w.deviceCursors)
			}
			run() // Reach the inactive Batch+1 row in both domains.
			if dryRun {
				count(3)
			} else {
				count(2)
			}
			if w.deviceCursors["admin"] != 0 || w.deviceCursors["user"] != 0 {
				t.Fatal("end did not wrap", w.deviceCursors)
			}
			if dryRun {
				w.Config.DryRun = false
				run()
				count(3)
				run()
				count(2)
			}
			// Previously skipped devices become eligible after logout. Wrap
			// must revisit them rather than leaving low IDs stranded forever.
			for _, session := range sessions {
				if err := (redis.SessionStore{}).Revoke(session.subject, session.sid); err != nil {
					t.Fatal(err)
				}
			}
			run()
			count(0)
			run() // An empty page also resets a full-page cursor.
			if w.deviceCursors["admin"] != 0 || w.deviceCursors["user"] != 0 {
				t.Fatal("empty page did not wrap")
			}
		})
	}
}

func testWorker(t *testing.T) *Worker {
	t.Helper()
	conn, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := conn.DB()
	sqlDB.SetMaxOpenConns(1)
	old := db.DB
	db.DB = conn
	t.Cleanup(func() { db.DB = old; _ = sqlDB.Close() })
	if err := conn.AutoMigrate(&db.User{}, &db.AdminUser{}, &db.RevocationOutbox{}, &db.AdminLoginLog{}, &db.UserLoginLog{}, &db.AdminAuditLog{}, &db.UserAuditLog{}, &db.UserSecurityEvent{}, &db.AdminSessionRow{}, &db.UserSessionRow{}, &db.SecurityGrant{}, &db.AdminMFAChallenge{}, &db.AdminMFA{}, &db.AdminDevice{}, &db.UserDevice{}); err != nil {
		t.Fatal(err)
	}
	return &Worker{DB: conn, Config: Config{Batch: 20, RetentionDays: 180, Interval: time.Hour}}
}

func TestRevocationRetryPreservesNewLogin(t *testing.T) {
	w := testWorker(t)
	r := miniredis.RunT(t)
	t.Setenv("REDIS_ADDR", r.Addr())
	t.Setenv("REDIS_PASSWORD", "")
	redis.InitRedis()
	if err := w.DB.Create(&db.User{ID: 1, OrganizationID: 1, Password: "before"}).Error; err != nil {
		t.Fatal(err)
	}
	store := redis.SessionStore{}
	old, err := store.Create("user", 1, 1, "old", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.MutateUserSecurity(w.DB, 1, 1, nil, map[string]any{"password": "after"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("user", old.SessionID); err == nil {
		t.Fatal("old access survived committed mutation")
	}
	fresh, err := store.Create("user", 1, 1, "new", "", time.Hour, redis.LoginMetadata{SessionVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	w.Revoke = func(string, int64, int64, int64) error { return errors.New("redis unavailable") }
	if err := w.RunRevocations(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var job db.RevocationOutbox
	if err := w.DB.First(&job).Error; err != nil {
		t.Fatal(err)
	}
	if job.CompletedAt != 0 || job.Attempts != 1 || job.NextAttemptAt <= now.Unix() {
		t.Fatal("retry not persisted")
	}
	w.Revoke = nil
	if err := w.RunRevocations(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("user", fresh.SessionID); err != nil {
		t.Fatal("new login revoked", err)
	}
	sessions, err := store.ListForUser("user", 1)
	if err != nil || len(sessions) != 1 || sessions[0].SessionID != fresh.SessionID {
		t.Fatal("old Redis record remains")
	}
	if err := w.RunRevocations(context.Background(), now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := db.MutateUserSecurity(w.DB, 1, 1, nil, map[string]any{"status": 2, "password": ""}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("user", fresh.SessionID); err == nil {
		t.Fatal("deleted account session survived")
	}
}

func TestRetentionPreservesActiveAndPending(t *testing.T) {
	w := testWorker(t)
	now := time.Now()
	old := now.Add(-365 * 24 * time.Hour).Unix()
	for _, row := range []any{
		&db.UserSessionRow{SessionID: "active", UserID: 1, OrganizationID: 1, Status: 1, ExpiresAt: old},
		&db.UserSessionRow{SessionID: "revoked", UserID: 1, OrganizationID: 1, Status: 2, ExpiresAt: old},
		&db.UserSecurityEvent{ID: "pending", SessionID: "s1", Status: "pending", CreatedAt: old},
		&db.UserSecurityEvent{ID: "resolved", SessionID: "s2", Status: "me", ResolvedAt: old, NotifyStatus: "sent"},
		&db.RevocationOutbox{Subject: "user", AccountID: 1, CreatedAt: old},
		&db.AdminMFAChallenge{Hash: "live", ExpiresAt: now.Add(time.Minute).Unix()},
	} {
		if err := w.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	w.Config.DryRun = true
	if n, err := w.RunRetention(context.Background(), now); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	w.Config.DryRun = false
	if n, err := w.RunRetention(context.Background(), now); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	for _, row := range []any{&db.UserSessionRow{}, &db.UserSecurityEvent{}, &db.RevocationOutbox{}, &db.AdminMFAChallenge{}} {
		var n int64
		if err := w.DB.Model(row).Count(&n).Error; err != nil || n != 1 {
			t.Fatal("protected row lost", n, err)
		}
	}
}

func TestWorkerStopJoins(t *testing.T) {
	w := testWorker(t)
	stop := w.Start(context.Background())
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker shutdown leaked")
	}
	stop() // idempotent
}

func TestRetentionPreservesLiveDevices(t *testing.T) {
	w := testWorker(t)
	r := miniredis.RunT(t)
	t.Setenv("REDIS_ADDR", r.Addr())
	t.Setenv("REDIS_PASSWORD", "")
	redis.InitRedis()
	if err := w.DB.Create(&db.User{ID: 1, OrganizationID: 1}).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-365 * 24 * time.Hour).Unix()
	for _, device := range []string{"live", "inactive"} {
		if err := w.DB.Create(&db.UserDevice{UserID: 1, OrganizationID: 1, DeviceID: device, LastUsedAt: old, LastActiveAt: old}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (redis.SessionStore{}).Create("user", 1, 1, "live", "", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := w.RunRetention(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var devices []db.UserDevice
	if err := w.DB.Find(&devices).Error; err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].DeviceID != "live" {
		t.Fatal("live device lost or inactive device retained")
	}
}
