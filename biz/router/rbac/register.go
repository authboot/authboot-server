package rbac

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/audit"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Register exposes the minimal fixed-role grant API; arbitrary role permissions
// are deliberately not accepted. Existing generated placeholder middleware is
// retained for compatibility with future IDL generation.
func Register(r *server.Hertz) {
	r.PUT("/api/v1/admin/organizations/:organization_id/members/:membership_id/role", jwt.AdminSessionAuth(), audit.Middleware(), setRole)
}

func setRole(ctx context.Context, c *app.RequestContext) {
	var req struct {
		Role string `json:"role"`
	}
	if c.BindAndValidate(&req) != nil || (req.Role != "admin" && req.Role != "member" && req.Role != "owner") {
		c.AbortWithStatus(400)
		return
	}
	orgID, _ := strconv.ParseInt(c.Param("organization_id"), 10, 64)
	memberID, _ := strconv.ParseInt(c.Param("membership_id"), 10, 64)
	actor := c.GetInt64(jwt.CtxKeyUserID)
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		// Serialize grants with other grants in this organization.
		var org db.Organization
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&org, orgID).Error; err != nil {
			return err
		}
		var owner db.OrganizationMembership
		if err := tx.Where("organization_id = ? AND account_id = ? AND role = 'owner' AND status = ?", orgID, actor, db.MembershipActive).First(&owner).Error; err != nil {
			return err
		}
		// Owner demotion/removal is not part of this first-batch API. This keeps
		// at least the existing owner and prevents concurrent last-owner loss.
		result := tx.Model(&db.OrganizationMembership{}).
			Where("id = ? AND organization_id = ? AND role <> 'owner' AND status = ?", memberID, orgID, db.MembershipActive).
			Update("role", req.Role)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
	if err != nil {
		c.AbortWithStatus(403)
		return
	}
	audit.Annotate(c, func(e *audit.Entry) {
		e.Action = "membership.role.update"
		e.ResourceType = "membership"
		e.ResourceID = strconv.FormatInt(memberID, 10)
		e.After, _ = json.Marshal(map[string]string{"role": req.Role})
		e.Success = true
	})
	c.JSON(200, map[string]interface{}{"code": 0, "message": "success"})
}
