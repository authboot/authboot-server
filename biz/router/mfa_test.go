package router_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/redis"
	sessionroute "github.com/authboot/authboot-server/biz/router/session"
	"github.com/authboot/authboot-server/pkg/utils"
)

func TestOrganizationUserRevokeAllRequiresStepUp(t *testing.T) {
	h := securityApp(t)
	sessionroute.Register(h)
	admin, access := newSession(t, "admin", 1, 1)
	victim, _ := newSession(t, "user", 1, 1)
	path := "/api/v1/organizations/1/users/1/sessions/revoke-all"
	grant := func(org int64) string {
		t.Helper()
		token, err := db.NewSecurityGrant(db.DB, db.SecurityGrant{
			Subject: "admin", AccountID: 1, OrganizationID: org,
			SessionID: admin.SessionID, Scope: "session:revoke",
		}, time.Now(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	for _, token := range []string{"", grant(2)} {
		status, _ := request(t, h, "POST", path, access, map[string]any{}, token)
		if status != 403 {
			t.Fatalf("invalid grant status: %d", status)
		}
		if _, err := (redis.SessionStore{}).Get("user", victim.SessionID); err != nil {
			t.Fatal("rejected request revoked session", err)
		}
	}
	token := grant(1)
	status, out := request(t, h, "POST", path, access, map[string]any{}, token)
	if status != 200 || out["code"] != float64(0) {
		t.Fatal(status, out)
	}
	if _, err := (redis.SessionStore{}).Get("user", victim.SessionID); err != redis.ErrSessionNotFound {
		t.Fatal("authorized revoke did not remove session", err)
	}
	fresh, _ := newSession(t, "user", 1, 1)
	if status, _ := request(t, h, "POST", path, access, map[string]any{}, token); status != 403 {
		t.Fatal("grant replay accepted", status)
	}
	if _, err := (redis.SessionStore{}).Get("user", fresh.SessionID); err != nil {
		t.Fatal("replay revoked new session", err)
	}
}

func TestAdminMFALifecycleHTTP(t *testing.T) {
	h := securityApp(t)
	t.Setenv("ADMIN_MFA_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("m", 32))))
	password := "Mfa-Test-Password-123!"
	hash, err := utils.Crypt(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Model(&db.AdminUser{}).Where("id = 1").Update("password", hash).Error; err != nil {
		t.Fatal(err)
	}
	old, access := newSession(t, "admin", 1, 0)
	step := func(scope, code string, recovery bool) string {
		t.Helper()
		status, out := request(t, h, "POST", "/api/v1/admin/auth/step-up", access, map[string]any{"password": password, "scope": scope, "code": code, "recovery": recovery})
		if status != 200 {
			t.Fatalf("stepup: %d %+v", status, out)
		}
		return out["step_up_token"].(string)
	}
	status, setup := request(t, h, "POST", "/api/v1/admin/auth/mfa/setup", access, map[string]any{}, step("mfa:setup", "", false))
	if status != 200 {
		t.Fatal(status, setup)
	}
	secret := setup["secret"].(string)
	code, err := utils.TOTP(secret, time.Now().Unix(), 6)
	if err != nil {
		t.Fatal(err)
	}
	status, confirmed := request(t, h, "POST", "/api/v1/admin/auth/mfa/confirm", access, map[string]any{"code": code}, step("mfa:confirm", "", false))
	if status != 200 {
		t.Fatal(status, confirmed)
	}
	recovery := confirmed["recovery_codes"].([]any)
	if len(recovery) != 10 {
		t.Fatal("missing recovery codes")
	}
	_, refresh := request(t, h, "POST", "/api/v1/admin/auth/refresh-token", "", map[string]any{"refresh_token": old.RefreshToken})
	if refresh["code"] == float64(0) {
		t.Fatal("old refresh bypassed MFA")
	}
	if status, _ := request(t, h, "POST", "/api/v1/admin/auth/logout", access, map[string]any{}); status != 401 {
		t.Fatal("old access accepted")
	}
	_, login := request(t, h, "POST", "/api/v1/admin/auth/login", "", map[string]any{"email": "owner@test", "password": password, "device_id": "mfa-device"})
	if login["mfa_required"] != true || login["access_token"] != "" || login["refresh_token"] != "" {
		t.Fatal("password-only session", login)
	}
	challenge := login["mfa_challenge_token"].(string)
	status, verified := request(t, h, "POST", "/api/v1/admin/auth/mfa/verify", "", map[string]any{"challenge_token": challenge, "code": recovery[0], "recovery": true})
	if status != 200 || verified["access_token"] == "" {
		t.Fatal("MFA login", status, verified)
	}
	if status, _ := request(t, h, "POST", "/api/v1/admin/auth/mfa/verify", "", map[string]any{"challenge_token": challenge, "code": recovery[1], "recovery": true}); status != 403 {
		t.Fatal("challenge replay accepted")
	}
	access = verified["access_token"].(string)
	rec, err := (redis.SessionStore{}).ByRefresh("admin", verified["refresh_token"].(string))
	if err != nil || rec.DeviceID != "mfa-device" {
		t.Fatal("challenge metadata lost")
	}
	status, disabled := request(t, h, "POST", "/api/v1/admin/auth/mfa/disable", access, map[string]any{}, step("mfa:disable", recovery[1].(string), true))
	if status != 200 {
		t.Fatal("disable", status, disabled)
	}
	if _, err := (redis.SessionStore{}).ByRefresh("admin", verified["refresh_token"].(string)); err == nil {
		t.Fatal("disable retained session")
	}
}

func TestUserStepUpUnbindHTTP(t *testing.T) {
	h := securityApp(t)
	hash, err := utils.Crypt("User-Step-Up-Password-123!")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Model(&db.User{}).Where("id = 1").Update("password", hash).Error; err != nil {
		t.Fatal(err)
	}
	for _, identity := range []db.UserIdentity{
		{OrganizationID: 1, UserID: 1, IdentityType: "email", IdentityValue: "user@example.test"},
		{OrganizationID: 1, UserID: 1, IdentityType: "username", IdentityValue: "user-name"},
	} {
		if err := db.DB.Create(&identity).Error; err != nil {
			t.Fatal(err)
		}
	}
	_, access := newSession(t, "user", 1, 1)
	_, other := newSession(t, "user", 1, 1)
	status, out := request(t, h, "POST", "/api/v1/user/auth/step-up", access, map[string]any{"password": "User-Step-Up-Password-123!", "scope": "identity:unbind"})
	if status != 200 {
		t.Fatal("user stepup", status, out)
	}
	grant := out["step_up_token"].(string)
	// Bind explicitly in JSON because this legacy endpoint has an enum path.
	path := "/api/v1/user/identities/1/unbind"
	body := map[string]any{"identity_type": 1, "identity_value": "user@example.test"}
	_, foreign := request(t, h, "POST", path, other, body, grant)
	if foreign["code"] == float64(0) {
		t.Fatal("cross-session proof accepted")
	}
	_, unbound := request(t, h, "POST", path, access, body, grant)
	if unbound["code"] != float64(0) {
		t.Fatal("unbind", unbound)
	}
	var count int64
	if err := db.DB.Model(&db.UserIdentity{}).Where("user_id = 1").Count(&count).Error; err != nil || count != 1 {
		t.Fatal("identity mutation", count, err)
	}
}

func TestDeleteAccountCommitsRevocationHTTP(t *testing.T) {
	h := securityApp(t)
	if err := db.DB.AutoMigrate(&db.UserAddress{}, &db.UserAuditLog{}, &db.Notification{}); err != nil {
		t.Fatal(err)
	}
	password := "Delete-Account-Password-123!"
	hash, err := utils.Crypt(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Model(&db.User{}).Where("id = 1").Updates(map[string]any{"password": hash, "settings": `{"private":"value"}`}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Create(&db.UserIdentity{OrganizationID: 1, UserID: 1, IdentityType: "email", IdentityValue: "delete@example.test"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Create(&db.Notification{UserID: 1, Title: "administrator notification"}).Error; err != nil {
		t.Fatal(err)
	}
	rec, access := newSession(t, "user", 1, 1)
	status, out := request(t, h, "POST", "/api/v1/user/auth/account/delete", access, map[string]any{"password": password})
	if status != 200 || out["code"] != float64(0) {
		t.Fatal("delete", status, out)
	}
	var user db.User
	if err := db.DB.First(&user, 1).Error; err != nil {
		t.Fatal(err)
	}
	if user.Password != "" || user.Status != 2 || user.SessionVersion != 1 || string(user.Settings) != "{}" {
		t.Fatal("anonymization/version not committed")
	}
	var pending int64
	if err := db.DB.Model(&db.RevocationOutbox{}).Where("subject = 'user' AND account_id = 1 AND completed_at = 0").Count(&pending).Error; err != nil || pending != 1 {
		t.Fatal("missing outbox", err)
	}
	var notifications int64
	if err := db.DB.Model(&db.Notification{}).Where("user_id = 1").Count(&notifications).Error; err != nil || notifications != 1 {
		t.Fatal("cross-domain notification deletion")
	}
	if _, err := (redis.SessionStore{}).ByRefresh("user", rec.RefreshToken); err == nil {
		t.Fatal("deleted account refresh remains usable")
	}
}
