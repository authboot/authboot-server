package router_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/redis"
	sessionroute "github.com/authboot/authboot-server/biz/router/session"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/authboot/authboot-server/pkg/utils"
	"github.com/cloudwego/hertz/pkg/app"
)

func TestDeviceHistoryPaginationAndCurrentMarker(t *testing.T) {
	h := securityApp(t)
	sessionroute.Register(h)
	if err := db.DB.AutoMigrate(&db.UserDevice{}, &db.UserSessionRow{}, &db.UserSecurityEvent{}); err != nil {
		t.Fatal(err)
	}
	store := redis.SessionStore{}
	current, err := store.Create("user", 1, 1, "current", "Phone", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("user", 1, 1, "current", "Phone", time.Hour); err != nil {
		t.Fatal(err)
	}
	token, _, err := jwt.GenerateUserAccessToken(1, 1, current.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Create(&db.UserDevice{OrganizationID: 1, UserID: 1, DeviceID: "current", LastUsedAt: 100}).Error; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 104; i++ {
		if err := db.DB.Create(&db.UserDevice{OrganizationID: 1, UserID: 1, DeviceID: fmt.Sprintf("old-%03d", i), LastUsedAt: 1}).Error; err != nil {
			t.Fatal(err)
		}
	}
	_, out := request(t, h, "GET", "/api/v1/me/security/devices?page_size=999&device_id=old-001", token, nil)
	devices, ok := out["devices"].([]interface{})
	if !ok || len(devices) != 100 || out["total"] != float64(105) {
		t.Fatal("pagination", out)
	}
	first := devices[0].(map[string]interface{})
	if first["device_id"] != "current" || first["current"] != true || first["active_sessions"] != float64(2) {
		t.Fatal("current from request or wrong count", first)
	}
	old := devices[1].(map[string]interface{})
	if old["status"] != "inactive" || old["active_sessions"] != float64(0) {
		t.Fatal("lost device history", old)
	}
	_, out = request(t, h, "GET", "/api/v1/me/security/devices?page=2&page_size=100", token, nil)
	if len(out["devices"].([]interface{})) != 5 {
		t.Fatal("last page", out)
	}
}

func TestSecurityCenterIsolationAndConfirmation(t *testing.T) {
	h := securityApp(t)
	sessionroute.Register(h)
	if err := db.DB.AutoMigrate(&db.UserDevice{}, &db.UserSessionRow{}, &db.UserSecurityEvent{}); err != nil {
		t.Fatal(err)
	}
	current, token := newSession(t, "user", 1, 1)
	suspect, suspectToken := newSession(t, "user", 1, 1)
	_, otherToken := newSession(t, "user", 2, 1)
	_, adminToken := newSession(t, "admin", 1, 1)
	hash, err := utils.Crypt("secure-password-123")
	if err != nil {
		t.Fatal(err)
	}
	db.DB.Model(&db.User{}).Where("id = ?", 1).Update("password", hash)
	for _, d := range []*db.UserDevice{
		{OrganizationID: 1, UserID: 1, DeviceID: "mine", DeviceName: "Mine"},
		{OrganizationID: 1, UserID: 2, DeviceID: "theirs", DeviceName: "Theirs"},
		{OrganizationID: 2, UserID: 1, DeviceID: "other-org", DeviceName: "Other org"},
	} {
		if err := db.DB.Create(d).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []*db.UserSecurityEvent{
		{ID: "mine", OrganizationID: 1, UserID: 1, SessionID: suspect.SessionID, Status: "pending"},
		{ID: "other-user", OrganizationID: 1, UserID: 2, SessionID: "other", Status: "pending"},
		{ID: "other-org", OrganizationID: 2, UserID: 1, SessionID: "other-org", Status: "pending"},
	} {
		if err := db.DB.Create(e).Error; err != nil {
			t.Fatal(err)
		}
	}
	base := "/api/v1/me/security"
	for _, path := range []string{"/devices", "/sessions", "/events"} {
		for _, badToken := range []string{"", adminToken} {
			if status, _ := request(t, h, "GET", base+path, badToken, nil); status != 401 {
				t.Fatal("unprotected", path, status)
			}
		}
	}
	for _, path := range []string{"/devices", "/events"} {
		_, out := request(t, h, "GET", base+path+"?organization_id=2&user_id=2&page_size=999", token, nil)
		if out["code"] != float64(errno.SuccessCode) || out["total"] != float64(1) {
			t.Fatalf("%s: %+v", path, out)
		}
	}
	proof := map[string]string{"event_id": "mine", "decision": "me", "password": "secure-password-123"}
	for _, tok := range []string{otherToken, suspectToken} {
		_, out := request(t, h, "POST", base+"/confirm", tok, proof)
		if out["code"] == float64(errno.SuccessCode) {
			t.Fatal("unsafe confirmation", out)
		}
	}
	proof["password"] = "wrong"
	_, out := request(t, h, "POST", base+"/confirm", token, proof)
	if out["code"] == float64(errno.SuccessCode) {
		t.Fatal("bad proof accepted")
	}
	proof["password"] = "secure-password-123"
	proof["event_id"] = "other-org"
	_, out = request(t, h, "POST", base+"/confirm", token, proof)
	if out["code"] == float64(errno.SuccessCode) {
		t.Fatal("cross-org confirmation")
	}
	proof["event_id"], proof["decision"] = "mine", "not_me"
	_, out = request(t, h, "POST", base+"/confirm", token, proof)
	if out["code"] != float64(errno.SuccessCode) || out["change_password_required"] != true {
		t.Fatal(out)
	}
	if _, err := (redis.SessionStore{}).Get("user", suspect.SessionID); err != redis.ErrSessionNotFound {
		t.Fatal("suspect survived", err)
	}
	if _, err := (redis.SessionStore{}).Get("user", current.SessionID); err != nil {
		t.Fatal("current lost", err)
	}
	if status, _ := request(t, h, "GET", base+"/events", suspectToken, nil); status != 401 {
		t.Fatal("revoked token accepted")
	}
	c := app.NewContext(0)
	c.Request.Header.SetMethod("GET")
	c.Request.SetRequestURI(base + "/confirm")
	c.Request.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(context.Background(), c)
	if c.Response.StatusCode() == 200 {
		t.Fatal("GET mutation exposed")
	}
}

func TestSecurityConfirmationBoundOTPAndMe(t *testing.T) {
	h := securityApp(t)
	sessionroute.Register(h)
	if err := db.DB.AutoMigrate(&db.UserDevice{}, &db.UserSessionRow{}, &db.UserSecurityEvent{}); err != nil {
		t.Fatal(err)
	}
	_, token := newSession(t, "user", 1, 1)
	suspect, _ := newSession(t, "user", 1, 1)
	for _, row := range []interface{}{
		&db.UserSecurityEvent{ID: "otp-event", OrganizationID: 1, UserID: 1, SessionID: suspect.SessionID, Status: "pending", CreatedAt: suspect.CreatedAt},
		&db.UserIdentity{OrganizationID: 1, UserID: 1, IdentityType: "email", IdentityValue: "owner@example.invalid", CreatedAt: suspect.CreatedAt - 10},
		&db.UserIdentity{OrganizationID: 1, UserID: 2, IdentityType: "email", IdentityValue: "other@example.invalid"},
	} {
		if err := db.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	codes := redis.Code{}
	if err := codes.Store("login", "other@example.invalid", "123456", time.Minute); err != nil {
		t.Fatal(err)
	}
	body := map[string]string{"event_id": "otp-event", "decision": "me", "identity_type": "email", "identity_value": "other@example.invalid", "credential": "123456"}
	_, out := request(t, h, "POST", "/api/v1/me/security/confirm", token, body)
	if out["code"] == float64(errno.SuccessCode) {
		t.Fatal("foreign contact proof accepted")
	}
	if err := codes.Store("login", "owner@example.invalid", "654321", time.Minute); err != nil {
		t.Fatal(err)
	}
	body["identity_value"] = "owner@example.invalid"
	body["credential"] = "bad"
	_, out = request(t, h, "POST", "/api/v1/me/security/confirm", token, body)
	if out["code"] == float64(errno.SuccessCode) {
		t.Fatal("wrong OTP accepted")
	}
	body["credential"] = "654321"
	_, out = request(t, h, "POST", "/api/v1/me/security/confirm", token, body)
	if out["code"] != float64(errno.SuccessCode) {
		t.Fatal(out)
	}
	if _, err := (redis.SessionStore{}).Get("user", suspect.SessionID); err != nil {
		t.Fatal("me revoked session", err)
	}
	var event db.UserSecurityEvent
	db.DB.First(&event, "id = ?", "otp-event")
	if event.Status != "me" {
		t.Fatal(event.Status)
	}
	if codes.Verify("login", "owner@example.invalid", "654321") {
		t.Fatal("OTP replay allowed")
	}
}

func TestSecurityMeRequiresHistoryAndNotMeIsIrreversible(t *testing.T) {
	h := securityApp(t)
	sessionroute.Register(h)
	if err := db.DB.AutoMigrate(&db.UserDevice{}, &db.UserSessionRow{}, &db.UserSecurityEvent{}); err != nil {
		t.Fatal(err)
	}
	a, aToken := newSession(t, "user", 1, 1)
	b, bToken := newSession(t, "user", 1, 1)
	hash, err := utils.Crypt("secure-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Model(&db.User{}).Where("id = ?", 1).Update("password", hash).Error; err != nil {
		t.Fatal(err)
	}
	for _, e := range []*db.UserSecurityEvent{
		{ID: "a-event", OrganizationID: 1, UserID: 1, SessionID: a.SessionID, CreatedAt: a.CreatedAt, Status: "pending"},
		{ID: "b-event", OrganizationID: 1, UserID: 1, SessionID: b.SessionID, CreatedAt: b.CreatedAt, Status: "pending"},
	} {
		if err := db.DB.Create(e).Error; err != nil {
			t.Fatal(err)
		}
	}
	confirm := func(token, id, decision string) map[string]interface{} {
		_, out := request(t, h, "POST", "/api/v1/me/security/confirm", token, map[string]string{
			"event_id": id, "decision": decision, "password": "secure-password-123"})
		return out
	}
	// Later and equal-second sessions cannot mutually approve with the password.
	if out := confirm(bToken, "a-event", "me"); out["code"] == float64(errno.SuccessCode) {
		t.Fatal(out)
	}
	if out := confirm(aToken, "b-event", "me"); out["code"] == float64(errno.SuccessCode) {
		t.Fatal(out)
	}
	// Even if B's event is strictly later, A's unresolved event prevents a chain.
	db.DB.Model(&db.UserSecurityEvent{}).Where("id = ?", "b-event").Update("created_at", a.CreatedAt+10)
	if out := confirm(aToken, "b-event", "me"); out["code"] == float64(errno.SuccessCode) {
		t.Fatal("unresolved A endorsed B", out)
	}
	// Model an established historical session without an unresolved event.
	h = securityApp(t)
	sessionroute.Register(h)
	if err := db.DB.AutoMigrate(&db.UserDevice{}, &db.UserSessionRow{}, &db.UserSecurityEvent{}); err != nil {
		t.Fatal(err)
	}
	db.DB.Model(&db.User{}).Where("id = ?", 1).Update("password", hash)
	b, _ = newSession(t, "user", 1, 1)
	if err := db.DB.Create(&db.UserSecurityEvent{ID: "b-event", OrganizationID: 1, UserID: 1, SessionID: b.SessionID, Status: "pending"}).Error; err != nil {
		t.Fatal(err)
	}
	historical, historicalToken := newSession(t, "user", 1, 1)
	db.DB.Model(&db.UserSecurityEvent{}).Where("id = ?", "b-event").Update("created_at", historical.CreatedAt+10)
	if out := confirm(historicalToken, "b-event", "me"); out["code"] != float64(errno.SuccessCode) {
		t.Fatal(out)
	}
	if out := confirm(historicalToken, "b-event", "me"); out["code"] != float64(errno.SuccessCode) {
		t.Fatal("me retry", out)
	}
	if out := confirm(historicalToken, "b-event", "not_me"); out["code"] != float64(errno.SuccessCode) || out["change_password_required"] != true {
		t.Fatal(out)
	}
	if _, err := (redis.SessionStore{}).Get("user", b.SessionID); err != redis.ErrSessionNotFound {
		t.Fatal("me blocked revocation", err)
	}
	if out := confirm(historicalToken, "b-event", "not_me"); out["code"] != float64(errno.SuccessCode) {
		t.Fatal("not_me retry", out)
	}
	if out := confirm(historicalToken, "b-event", "me"); out["code"] == float64(errno.SuccessCode) {
		t.Fatal("reversed not_me", out)
	}
	var event db.UserSecurityEvent
	db.DB.First(&event, "id = ?", "b-event")
	if event.Status != "not_me" {
		t.Fatal(event.Status)
	}
}

func TestSecurityCenterBulkRevokeUsesAuthenticatedSession(t *testing.T) {
	h := securityApp(t)
	sessionroute.Register(h)
	if err := db.DB.AutoMigrate(&db.UserDevice{}, &db.UserSessionRow{}, &db.UserSecurityEvent{}); err != nil {
		t.Fatal(err)
	}
	store := redis.SessionStore{}
	current, token := newSession(t, "user", 1, 1)
	other, _ := newSession(t, "user", 1, 1)
	_, out := request(t, h, "POST", "/api/v1/me/security/revoke", token, map[string]string{"mode": "others", "session_id": other.SessionID, "keep": other.SessionID})
	if out["code"] != float64(errno.SuccessCode) || out["revoked_sessions"] != float64(1) {
		t.Fatal(out)
	}
	if _, err := store.Get("user", current.SessionID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := store.Create("user", 1, 1, "phone", "Phone", time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	_, out = request(t, h, "POST", "/api/v1/me/security/revoke", token, map[string]string{"mode": "device", "device_id": "phone"})
	if out["code"] != float64(errno.SuccessCode) || out["revoked_sessions"] != float64(2) {
		t.Fatal(out)
	}
	// A user token's claimed organization must also match its live session.
	wrongOrg, _, err := jwt.GenerateUserAccessToken(1, 2, current.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := request(t, h, "GET", "/api/v1/me/security/devices", wrongOrg, nil); status != 401 {
		t.Fatal("org bypass", status)
	}
}
