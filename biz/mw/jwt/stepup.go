package jwt

import (
	"strings"
	"time"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/pkg/securitymetrics"
	"github.com/cloudwego/hertz/pkg/app"
)

func ValidAdminStepUpScope(scope string) bool {
	switch scope {
	case "mfa:setup", "mfa:confirm", "mfa:disable", "mfa:recovery",
		"organization:delete", "member:manage", "oauth:manage", "session:revoke":
		return true
	}
	return false
}

// Called only after resource authorization. MFA actions consume within their
// business transaction; self-logout and ordinary refresh/read are not gated.
func adminStepUpScope(c *app.RequestContext) string {
	path, method := c.FullPath(), string(c.Method())
	if method == "GET" || method == "HEAD" {
		return ""
	}
	// This management route uses AdminSessionAuth despite lacking /admin.
	if method == "POST" && path == "/api/v1/organizations/:organization_id/users/:user_id/sessions/revoke-all" {
		return "session:revoke"
	}
	if method == "DELETE" && path == "/api/v1/admin/organizations/:organization_id" {
		return "organization:delete"
	}
	if strings.Contains(path, "/members/") && strings.HasSuffix(path, "/role") || method == "DELETE" && strings.Contains(path, "/memberships/") {
		return "member:manage"
	}
	if strings.Contains(path, "/oauth/") && strings.HasPrefix(path, "/api/v1/admin/") {
		return "oauth:manage"
	}
	if strings.HasPrefix(path, "/api/v1/admin/") && strings.Contains(path, "/sessions") && (strings.HasSuffix(path, "/revoke") || strings.HasSuffix(path, "/revoke-all")) {
		if c.Param("session_id") != c.GetString(CtxKeySessionID) {
			return "session:revoke"
		}
	}
	return ""
}

func consumeAdminStepUp(c *app.RequestContext) bool {
	scope := adminStepUpScope(c)
	if scope == "" {
		return true
	}
	err := db.ConsumeSecurityGrant(db.DB, string(c.GetHeader("X-Step-Up-Token")), db.SecurityGrant{
		Subject: SubjectAdmin, AccountID: c.GetInt64(CtxKeyUserID), OrganizationID: c.GetInt64(CtxKeyOrgID),
		SessionID: c.GetString(CtxKeySessionID), Scope: scope,
	}, time.Now())
	if err != nil {
		securitymetrics.Add("stepup_failure_total", 1)
	}
	return err == nil
}
