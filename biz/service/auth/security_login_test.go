package auth

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestLoginSucceedsWhenSecurityNotificationOrPersistenceFails(t *testing.T) {
	server := miniredis.RunT(t)
	t.Setenv("REDIS_ADDR", server.Addr())
	t.Setenv("REDIS_PASSWORD", "")
	t.Setenv("JWT_SECRET_KEY_USER", "isolated-security-login-test")
	t.Setenv("IP2REGION_DB_PATH", "")
	t.Setenv("GEOLITE2_CITY_DB_PATH", "")
	redis.InitRedis()
	conn, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := conn.DB()
	sqlDB.SetMaxOpenConns(1)
	old := db.DB
	db.DB = conn
	t.Cleanup(func() { db.DB = old; _ = sqlDB.Close() })
	if err := conn.AutoMigrate(&db.User{}, &db.Organization{}, &db.UserIdentity{}, &db.UserDevice{}, &db.UserSessionRow{}, &db.UserSecurityEvent{}); err != nil {
		t.Fatal(err)
	}
	u := &db.User{ID: 1, OrganizationID: 1, Status: 1}
	for _, row := range []interface{}{&db.Organization{ID: 1, Name: "test", Code: "test", Status: 1}, u, &db.UserIdentity{OrganizationID: 1, UserID: 1, IdentityType: "email", IdentityValue: "nobody@example.invalid"}} {
		if err := conn.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	service := NewAuthService(context.Background(), app.NewContext(0))
	// email.Init is intentionally never called. email.Send fails before network IO.
	response, err := service.buildLoginResponse(u, 0, "phone", "Phone")
	if err != nil || response.AccessToken == "" || len(response.SecurityEventIds) != 1 {
		t.Fatalf("%+v %v", response, err)
	}
	var event db.UserSecurityEvent
	if err := conn.First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if event.NotifyStatus != "pending" || event.NotifyAttempts != 1 {
		t.Fatalf("%+v", event)
	}
	again, err := service.buildLoginResponse(u, 0, "phone", "Phone")
	if err != nil || len(again.SecurityEventIds) != 0 {
		t.Fatal("repeat login alert", err)
	}
	var count int64
	conn.Model(&db.UserSecurityEvent{}).Count(&count)
	if count != 1 {
		t.Fatal(count)
	}
	if err := conn.Migrator().DropTable(&db.UserSecurityEvent{}); err != nil {
		t.Fatal(err)
	}
	response, err = service.buildLoginResponse(u, 0, "new-device", "New")
	if err != nil || response.AccessToken == "" {
		t.Fatal("best-effort persistence blocked login", err)
	}
}
