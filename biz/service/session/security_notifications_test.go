package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/email"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestSecurityNotificationRetryAndRecipientIsolation(t *testing.T) {
	conn, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := conn.DB()
	sqlDB.SetMaxOpenConns(1)
	old := db.DB
	db.DB = conn
	t.Cleanup(func() { db.DB = old; _ = sqlDB.Close() })
	if err := conn.AutoMigrate(&db.UserIdentity{}, &db.UserSecurityEvent{}); err != nil {
		t.Fatal(err)
	}
	for _, identity := range []*db.UserIdentity{
		{OrganizationID: 1, UserID: 1, IdentityType: "email", IdentityValue: "owner@example.invalid"},
		{OrganizationID: 2, UserID: 1, IdentityType: "email", IdentityValue: "other-org@example.invalid"},
		{OrganizationID: 1, UserID: 2, IdentityType: "email", IdentityValue: "other-user@example.invalid"},
	} {
		if err := conn.Create(identity).Error; err != nil {
			t.Fatal(err)
		}
	}
	event := &db.UserSecurityEvent{ID: "event", OrganizationID: 1, UserID: 1, SessionID: "session", NotifyStatus: "pending"}
	if err := conn.Create(event).Error; err != nil {
		t.Fatal(err)
	}
	calls := 0
	sender := func(ctx context.Context, msg *email.Message) error {
		calls++
		if len(msg.To) != 1 || msg.To[0] != "owner@example.invalid" {
			t.Fatalf("wrong recipient: %+v", msg.To)
		}
		if deadline, ok := ctx.Deadline(); !ok {
			t.Fatal("no send timeout")
		} else {
			var claimed db.UserSecurityEvent
			if err := conn.First(&claimed, "id = ?", "event").Error; err != nil {
				t.Fatal(err)
			}
			if time.Until(deadline) > securityNotificationTimeout || !deadline.Before(time.Unix(claimed.NotifyAfter, 0)) {
				t.Fatal("send deadline exceeds timeout or lease")
			}
		}
		if calls == 1 {
			return errors.New("simulated delivery failure")
		}
		return nil
	}
	retrySecurityNotifications(context.Background(), 1, 1, sender)
	if err := conn.First(event, "id = ?", "event").Error; err != nil {
		t.Fatal(err)
	}
	if event.NotifyStatus != "pending" || event.NotifyAttempts != 1 {
		t.Fatalf("%+v", event)
	}
	retrySecurityNotifications(context.Background(), 1, 1, sender)
	if calls != 1 {
		t.Fatal("lease bypass")
	}
	conn.Model(event).Update("notify_after", 0)
	retrySecurityNotifications(context.Background(), 1, 1, sender)
	if err := conn.First(event, "id = ?", "event").Error; err != nil {
		t.Fatal(err)
	}
	if event.NotifyStatus != "sent" || event.NotifyAttempts != 2 {
		t.Fatalf("%+v", event)
	}
	retrySecurityNotifications(context.Background(), 1, 1, sender)
	if calls != 2 {
		t.Fatal("sent message retried")
	}
	conn.Model(event).Updates(map[string]interface{}{"notify_status": "pending", "notify_attempts": 3, "notify_after": 0})
	retrySecurityNotifications(context.Background(), 1, 1, sender)
	conn.First(event, "id = ?", "event")
	if calls != 2 || event.NotifyStatus != "failed" {
		t.Fatal("attempt budget not enforced")
	}
}

func TestClientSummaryIsDisplayOnly(t *testing.T) {
	browser, os := ClientSummary("Mozilla/5.0 (Windows NT 10.0) Chrome/130.0 Safari/537.36 Edg/130.0")
	if browser != "Edge" || os != "Windows" {
		t.Fatal(browser, os)
	}
	browser, os = ClientSummary("unrecognized")
	if browser != "Unknown" || os != "Unknown" {
		t.Fatal(browser, os)
	}
}
