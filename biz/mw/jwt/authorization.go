package jwt

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/cloudwego/hertz/pkg/app"
)

// Applied by every AdminSessionAuth route, including resource-id-only routes.
func authorizeAdminResource(c *app.RequestContext, accountID, tokenOrg int64) bool {
	// A resource authorized by its path must not be replaced during binding by
	// a conflicting body, query or form identifier.
	var identifiers map[string]json.RawMessage
	if strings.Contains(string(c.ContentType()), "application/json") && len(c.Request.Body()) > 0 {
		if json.Unmarshal(c.Request.Body(), &identifiers) != nil {
			return false
		}
	}
	for _, p := range c.Params {
		if !strings.HasSuffix(p.Key, "_id") {
			continue
		}
		for _, raw := range []string{c.Query(p.Key), c.PostForm(p.Key)} {
			if raw != "" && raw != p.Value {
				return false
			}
		}
		if raw, ok := identifiers[p.Key]; ok && strings.Trim(string(raw), `"`) != p.Value {
			return false
		}
	}
	orgID := int64(0)
	permission := "resource:read"
	write := string(c.Method()) != "GET" && string(c.Method()) != "HEAD"
	if write {
		permission = "resource:write"
	}
	if raw := c.Param("organization_id"); raw != "" {
		var err error
		orgID, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || orgID <= 0 {
			return false
		}
		path := string(c.Path())
		if strings.Contains(path, "/members") || strings.Contains(path, "/invitations") || strings.Contains(path, "/roles") {
			permission = "member:manage"
		}
		// Organization settings and lifecycle require workspace management permission.
		tail := strings.SplitN(path, "/organizations/"+raw, 2)
		if write && len(tail) == 2 && (tail[1] == "" || tail[1] == "/settings" || tail[1] == "/logo") {
			permission = "organization:manage"
		}
		if len(tail) == 2 && tail[1] == "/leave" {
			permission = "membership:self"
		}
	} else if raw := c.Param("membership_id"); raw != "" {
		var m db.OrganizationMembership
		if db.DB.Where("id = ?", raw).First(&m).Error != nil || (write && m.Role == "owner") {
			return false
		}
		orgID, permission = m.OrganizationID, "member:manage"
	} else if raw := c.Param("invitation_id"); raw != "" {
		var inv db.OrganizationInvitation
		if db.DB.Where("id = ?", raw).First(&inv).Error != nil {
			return false
		}
		orgID, permission = inv.OrganizationID, "member:manage"
	}
	if orgID != 0 {
		// Reject conflicting body/query scopes before the handler binds them.
		for _, raw := range []string{c.Query("organization_id"), c.PostForm("organization_id")} {
			if raw != "" && raw != strconv.FormatInt(orgID, 10) {
				return false
			}
		}
		if strings.Contains(string(c.ContentType()), "application/json") && len(c.Request.Body()) > 0 {
			var body map[string]json.RawMessage
			if json.Unmarshal(c.Request.Body(), &body) != nil {
				return false
			}
			if raw, ok := body["organization_id"]; ok {
				value := strings.Trim(string(raw), `"`)
				id, err := strconv.ParseInt(value, 10, 64)
				if err != nil || id != orgID {
					return false
				}
			}
		}
		if tokenOrg != orgID || db.AuthorizeOrganization(accountID, orgID, permission) != nil {
			return false
		}
		if write && strings.HasSuffix(c.FullPath(), "/members/:membership_id/role") {
			if db.AuthorizeOrganization(accountID, orgID, "organization:manage") != nil {
				return false
			}
			var target db.OrganizationMembership
			if db.DB.Where("id = ? AND organization_id = ? AND role <> 'owner' AND status = ?", c.Param("membership_id"), orgID, db.MembershipActive).First(&target).Error != nil {
				return false
			}
		}
		c.Set(authorizedOrgKey, orgID)
		return true
	}
	// Platform accounts may only inspect/revoke their own admin sessions.
	if raw := c.Param("account_id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		return err == nil && id == accountID
	}
	if sid := c.Param("session_id"); sid != "" && strings.HasPrefix(string(c.Path()), "/api/v1/admin/") {
		rec, err := sessionStore.Get(SubjectAdmin, sid)
		return err == nil && rec.AccountID == accountID
	}
	// Unscoped access is limited to explicit account self-service endpoints.
	// Match registered notification patterns, not an arbitrary URL prefix.
	switch c.FullPath() {
	case "/api/v1/admin/notifications", "/api/v1/admin/notifications/check-new",
		"/api/v1/admin/notifications/read-all", "/api/v1/admin/notifications/:id",
		"/api/v1/admin/notifications/:id/read":
		return true // NotificationDAO always scopes reads/writes to current_user_id.
	}
	switch string(c.Path()) {
	case "/api/v1/admin/me", "/api/v1/admin/me/settings", "/api/v1/admin/me/avatar",
		"/api/v1/admin/auth/step-up",
		"/api/v1/admin/auth/mfa/setup", "/api/v1/admin/auth/mfa/confirm",
		"/api/v1/admin/auth/mfa/disable", "/api/v1/admin/auth/mfa/recovery",
		"/api/v1/admin/auth/logout", "/api/v1/admin/auth/switch-organization",
		"/api/v1/admin/organizations", "/api/v1/invitations/accept":
		return true
	case "/api/v1/admin/message-providers":
		// Read-only catalog from the backend registry; carries no tenant data.
		return !write
	default:
		return false
	}
}
