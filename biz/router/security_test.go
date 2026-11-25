package router_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/captcha"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/redis"
	authroute "github.com/authboot/authboot-server/biz/router/auth"
	messageroute "github.com/authboot/authboot-server/biz/router/message"
	orgroute "github.com/authboot/authboot-server/biz/router/organization"
	"github.com/authboot/authboot-server/biz/router/rbac"
	userroute "github.com/authboot/authboot-server/biz/router/user"
	"github.com/authboot/authboot-server/pkg/clientip"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	jwtv4 "github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func securityApp(t *testing.T) *server.Hertz {
	t.Helper()
	r := miniredis.RunT(t)
	t.Setenv("REDIS_ADDR", r.Addr())
	t.Setenv("REDIS_PASSWORD", "")
	t.Setenv("JWT_SECRET_KEY_USER", "isolated-user-test-key")
	t.Setenv("JWT_SECRET_KEY_ADMIN", "isolated-admin-test-key")
	redis.InitRedis()
	captcha.Init()
	conn, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := conn.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	db.DB = conn
	db.IOrganizationDAO = db.NewOrganizationDAO(conn)
	db.IOrganizationMembershipDAO = db.NewOrganizationMembershipDAO(conn)
	db.IUserDAO = db.NewUserDAO(conn)
	db.IUserIdentityDAO = db.NewUserIdentityDAO(conn)
	if err := conn.AutoMigrate(&db.Organization{}, &db.OrganizationMembership{}, &db.AdminUser{}, &db.User{}, &db.UserIdentity{}, &db.SecurityGrant{}, &db.AdminMFA{}, &db.AdminMFARecovery{}, &db.AdminMFAChallenge{}, &db.RevocationOutbox{}); err != nil {
		t.Fatal(err)
	}
	for _, row := range []interface{}{
		&db.Organization{ID: 1, Name: "one", Code: "one", Status: 1},
		&db.Organization{ID: 2, Name: "two", Code: "two", Status: 1},
		&db.User{ID: 1, OrganizationID: 1, Status: 1},
		&db.User{ID: 2, OrganizationID: 1, Status: 1},
		&db.AdminUser{ID: 1, Email: "owner@test", Status: 1},
		&db.AdminUser{ID: 2, Email: "admin@test", Status: 1},
		&db.AdminUser{ID: 3, Email: "member@test", Status: 1},
		&db.OrganizationMembership{ID: 1, OrganizationID: 1, AccountID: 1, Role: "owner", Status: db.MembershipActive},
		&db.OrganizationMembership{ID: 2, OrganizationID: 1, AccountID: 2, Role: "admin", Status: db.MembershipActive},
		&db.OrganizationMembership{ID: 3, OrganizationID: 1, AccountID: 3, Role: "member", Status: db.MembershipActive},
		&db.OrganizationMembership{ID: 4, OrganizationID: 2, AccountID: 1, Role: "member", Status: db.MembershipActive},
	} {
		if err := conn.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	h := server.New()
	authroute.Register(h)
	messageroute.Register(h)
	orgroute.Register(h)
	userroute.Register(h)
	rbac.Register(h)
	return h
}

func request(t *testing.T, h *server.Hertz, method, path, token string, body interface{}, stepup ...string) (int, map[string]interface{}) {
	t.Helper()
	c := app.NewContext(0)
	c.Request.SetRequestURI(path)
	c.Request.Header.SetMethod(method)
	c.Request.Header.Set("Content-Type", "application/json")
	if len(stepup) > 0 {
		c.Request.Header.Set("X-Step-Up-Token", stepup[0])
	}
	if token != "" {
		c.Request.Header.Set("Authorization", "Bearer "+token)
	}
	b, _ := json.Marshal(body)
	c.Request.SetBody(b)
	c.Request.Header.SetContentLength(len(b))
	h.ServeHTTP(context.Background(), c)
	result := map[string]interface{}{}
	if len(c.Response.Body()) > 0 {
		if err := json.Unmarshal(c.Response.Body(), &result); err != nil {
			t.Fatalf("response %d: %s", c.Response.StatusCode(), c.Response.Body())
		}
	}
	return c.Response.StatusCode(), result
}

func newSession(t *testing.T, subject string, id, org int64) (*redis.SessionRecord, string) {
	t.Helper()
	rec, err := (redis.SessionStore{}).Create(subject, id, org, "", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var token string
	if subject == "user" {
		token, _, err = jwt.GenerateUserAccessToken(id, org, rec.SessionID)
	} else {
		token, _, err = jwt.GenerateAdminAccessToken(id, org, rec.SessionID, time.Hour)
	}
	if err != nil {
		t.Fatal(err)
	}
	return rec, token
}

func TestLogoutOwnershipAndExpiredAccessRefresh(t *testing.T) {
	h := securityApp(t)
	one, access := newSession(t, "user", 1, 1)
	two, _ := newSession(t, "user", 2, 1)
	path := "/api/v1/user/auth/logout"
	if status, _ := request(t, h, "POST", path, "", map[string]string{"session_id": two.SessionID}); status != 401 {
		t.Fatal(status)
	}
	_, result := request(t, h, "POST", path, access, map[string]string{"session_id": two.SessionID})
	if result["code"] == float64(errno.SuccessCode) {
		t.Fatal("cross-user logout accepted")
	}
	if _, err := (redis.SessionStore{}).Get("user", two.SessionID); err != nil {
		t.Fatal("victim revoked")
	}
	expired, _ := jwtv4.NewWithClaims(jwtv4.SigningMethodHS256, jwt.UserClaims{
		UserID: 1, OrganizationID: 1, SessionID: one.SessionID,
		RegisteredClaims: jwtv4.RegisteredClaims{ExpiresAt: jwtv4.NewNumericDate(time.Now().Add(-time.Hour))},
	}).SignedString([]byte("isolated-user-test-key"))
	if _, err := jwt.ParseUserToken(expired); err == nil {
		t.Fatal("test token not expired")
	}
	_, result = request(t, h, "POST", "/api/v1/user/auth/refresh-token", expired, map[string]string{"refresh_token": one.RefreshToken})
	if result["code"] != float64(errno.SuccessCode) || result["refresh_token"] == "" {
		t.Fatalf("refresh rejected: %+v", result)
	}
	_, replay := request(t, h, "POST", "/api/v1/user/auth/refresh-token", "", map[string]string{"refresh_token": one.RefreshToken})
	if replay["code"] == float64(errno.SuccessCode) {
		t.Fatal("replay accepted")
	}
	_, result = request(t, h, "POST", path, access, map[string]string{})
	if result["code"] != float64(errno.SuccessCode) {
		t.Fatal(result)
	}
	if _, err := (redis.SessionStore{}).Get("user", one.SessionID); err != redis.ErrSessionNotFound {
		t.Fatal("current session not revoked", err)
	}
}

func TestOrganizationAndRoleBoundaries(t *testing.T) {
	h := securityApp(t)
	_, owner := newSession(t, "admin", 1, 1)
	_, admin := newSession(t, "admin", 2, 1)
	_, member := newSession(t, "admin", 3, 1)
	for _, tc := range []struct {
		token, path string
		status      int
	}{
		{owner, "/api/v1/admin/organizations/1", 200},
		{owner, "/api/v1/admin/organizations/2", 403},
		{member, "/api/v1/admin/organizations/1/users", 200},
		{member, "/api/v1/admin/organizations/2", 403},
		{admin, "/api/v1/admin/organizations/1", 200},
		{admin, "/api/v1/admin/organizations/2", 403},
	} {
		if status, _ := request(t, h, "GET", tc.path, tc.token, nil); status != tc.status {
			t.Fatalf("%s: %d", tc.path, status)
		}
	}
	path := "/api/v1/admin/organizations/1/members/3/role"
	for _, permission := range []string{"organization:manage", "member:manage", "resource:write"} {
		if err := db.AuthorizeOrganization(3, 1, permission); err != nil {
			t.Fatalf("backend member lacks %s: %v", permission, err)
		}
	}
	if status, _ := request(t, h, "PUT", path, admin, map[string]string{"role": "owner"}); status != 403 {
		t.Fatal("role change without step-up grant", status)
	}
	if status, _ := request(t, h, "PUT", "/api/v1/admin/organizations/1/members/4/role", owner, map[string]string{"role": "admin"}); status != 403 {
		t.Fatal("cross-org grant", status)
	}
	if err := db.AuthorizeOrganization(2, 1, "organization:manage"); err != nil {
		t.Fatal("workspace admin cannot manage settings", err)
	}
	claims, err := jwt.ParseAdminToken(admin)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := db.NewSecurityGrant(db.DB, db.SecurityGrant{Subject: "admin", AccountID: 2, OrganizationID: 1, SessionID: claims.SessionID, Scope: "member:manage"}, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := request(t, h, "PUT", path, admin, map[string]string{"role": "admin"}, grant); status != 200 {
		t.Fatal("workspace admin role grant", status)
	}
	if status, _ := request(t, h, "GET", "/api/v1/admin/organizations/1", member, nil); status != 200 {
		t.Fatal("grant not effective", status)
	}
	db.DB.Model(&db.OrganizationMembership{}).Where("id = 3").Update("status", 3)
	if status, _ := request(t, h, "GET", "/api/v1/admin/organizations/1", member, nil); status != 401 {
		t.Fatal("disabled membership accepted", status)
	}
}

func TestCaptchaBypassAndOneTimeGrant(t *testing.T) {
	h := securityApp(t)
	send := map[string]interface{}{"target": "nobody@example.test", "scene": 1, "channel": 2}
	_, result := request(t, h, "POST", "/api/v1/message/send-code", "", send)
	if result["code"] == float64(errno.SuccessCode) {
		t.Fatal("captcha bypass")
	}
	// A deterministic image challenge uses the actual shared Redis store.
	(redis.CaptchaStore{TTL: time.Minute}).Set("challenge", "12345")
	c := app.NewContext(0)
	// Hertz's no-network test context uses this same client IP fallback.
	binding := "1:" + clientip.FromContext(c)
	if err := (redis.Code{}).Store("captcha_binding", "challenge", binding, time.Minute); err != nil {
		t.Fatal(err)
	}
	_, result = request(t, h, "POST", "/api/v1/captcha/verify", "", map[string]interface{}{"captcha_id": "challenge", "answer": "12345", "scene": 1})
	if result["code"] != float64(errno.SuccessCode) || result["verify_token"] == "" {
		t.Fatal(result)
	}
	token := result["verify_token"].(string)
	_, replay := request(t, h, "POST", "/api/v1/captcha/verify", "", map[string]interface{}{"captcha_id": "challenge", "answer": "12345", "scene": 1})
	if replay["code"] == float64(errno.SuccessCode) {
		t.Fatal("captcha replay")
	}
	send["captcha_verify_token"] = token
	_, _ = request(t, h, "POST", "/api/v1/message/send-code", "", send) // Unconfigured delivery must fail closed.
	if (redis.Code{}).Verify("captcha_grant", token, binding) {
		t.Fatal("grant not consumed")
	}
}

func TestLegacyPasswordLoginUpgradesOnlySuccessfulAuthentication(t *testing.T) {
	h := securityApp(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("old"), 5)
	db.DB.Model(&db.User{}).Where("id = 1").Update("password", string(hash))
	db.DB.Create(&db.UserIdentity{OrganizationID: 1, UserID: 1, IdentityType: "username", IdentityValue: "legacy"})
	for _, password := range []string{"wrong", "old"} {
		_, result := request(t, h, "POST", "/api/v1/user/auth/login", "", map[string]interface{}{"organization_id": 1, "username": "legacy", "password": password})
		var user db.User
		db.DB.First(&user, 1)
		cost, _ := bcrypt.Cost([]byte(user.Password))
		if password == "wrong" && cost != 5 {
			t.Fatal("failed login upgraded hash")
		}
		if password == "old" && (cost != bcrypt.DefaultCost || result["code"] != float64(errno.SuccessCode)) {
			t.Fatal("legacy upgrade failed", cost, result)
		}
	}
}
