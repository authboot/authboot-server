package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/model/auth"
	"github.com/authboot/authboot-server/biz/mw/audit"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/authboot/authboot-server/pkg/utils"
)

type AdminAuthService struct {
	ctx context.Context
	c   *app.RequestContext

	organizationMembershipDAO *db.OrganizationMembershipDAO
}

func NewAdminAuthService(ctx context.Context, c *app.RequestContext) *AdminAuthService {
	return &AdminAuthService{
		ctx: ctx,
		c:   c,

		organizationMembershipDAO: db.IOrganizationMembershipDAO,
	}
}

func (s *AdminAuthService) AdminLogin(req *auth.AdminLoginRequest) (*auth.AdminLoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, errno.ParamErr
	}

	// recordAdminLogin 把本次登录结果写入 tb_admin_login_logs（best-effort：
	// 失败只记日志，不影响登录主流程）。
	recordAdminLogin := func(adminID int64, email string, success bool, errMsg string) {
		log := &db.AdminLoginLog{
			AdminID:    adminID,
			Email:      email,
			DeviceID:   req.DeviceId,
			DeviceName: req.DeviceName,
			IP:         s.c.ClientIP(),
			UserAgent:  string(s.c.UserAgent()),
			Success:    success,
			ErrMsg:     errMsg,
		}
		if err := db.InsertAdminLoginLog(log); err != nil {
			hlog.CtxErrorf(s.ctx, "record admin login log: %v", err)
		}
	}

	user, err := db.QueryAdminUser(req.Email)
	if err != nil {
		audit.Record(s.c, &audit.Entry{
			Action:  "admin.login",
			Success: false,
			ErrMsg:  "account not found",
			Extra:   auditExtra(map[string]any{"email": req.Email}),
		})
		recordAdminLogin(0, req.Email, false, "account not found")
		return nil, err
	}

	fmt.Println(utils.Crypt(req.Password))

	if ok := utils.VerifyPassword(req.Password, user.Password); !ok {
		audit.Record(s.c, &audit.Entry{
			Action:  "admin.login",
			AdminID: user.ID,
			Success: false,
			ErrMsg:  "password mismatch",
			Extra:   auditExtra(map[string]any{"email": req.Email}),
		})
		recordAdminLogin(user.ID, req.Email, false, "password mismatch")
		return nil, errno.PasswordIsNotVerified
	}

	// Open a server-side admin session. Login does NOT bind an organization:
	// the account may belong to several orgs, so the token is issued org-unbound
	// (organization id 0 = platform/unbound) and the caller picks an org via
	// SwitchOrganization, which re-scopes the token to that org.
	rec, err := sessionStore.Create(jwt.SubjectAdmin, user.ID, 0, req.DeviceId, req.DeviceName, redis.DefaultSessionTTL)
	if err != nil {
		return nil, err
	}
	accessToken, accessExp, err := jwt.GenerateAdminAccessToken(rec.AccountID, rec.OrganizationID, rec.SessionID, s.adminAccessTTL(rec.OrganizationID))
	if err != nil {
		return nil, err
	}

	audit.Record(s.c, &audit.Entry{
		Action:    "admin.login",
		AdminID:   user.ID,
		SessionID: rec.SessionID,
		Success:   true,
	})
	recordAdminLogin(user.ID, req.Email, true, "")
	// 登记设备（best-effort：首见插入，复登更新 last_used_at / login_count）
	if err := db.UpsertAdminDevice(user.ID, req.DeviceId, req.DeviceName, s.c.ClientIP(), string(s.c.UserAgent()), time.Now().Unix()); err != nil {
		hlog.CtxErrorf(s.ctx, "upsert admin device %s: %v", req.DeviceId, err)
	}
	return &auth.AdminLoginResponse{
		Code:                  errno.SuccessCode,
		Message:               errno.SuccessMsg,
		AccessToken:           accessToken,
		RefreshToken:          rec.RefreshToken,
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: rec.ExpiresAt,
	}, nil
}

// AdminRefreshToken rotates the presented refresh token on its session and
// issues a fresh short-lived access token. A replayed / unknown token is rejected.
func (s *AdminAuthService) AdminRefreshToken(req *auth.AdminRefreshTokenRequest) (*auth.AdminLoginResponse, error) {
	if req.RefreshToken == "" {
		return nil, errno.ParamErr
	}
	rec, err := sessionStore.Rotate(jwt.SubjectAdmin, req.RefreshToken, redis.DefaultSessionTTL)
	if err != nil {
		if errors.Is(err, redis.ErrSessionNotFound) {
			audit.Record(s.c, &audit.Entry{
				Action:  "admin.refresh_token",
				Success: false,
				ErrMsg:  "invalid or replayed refresh token",
			})
			return nil, errno.AuthorizationFailedErr
		}
		return nil, err
	}
	accessToken, accessExp, err := jwt.GenerateAdminAccessToken(rec.AccountID, rec.OrganizationID, rec.SessionID, s.adminAccessTTL(rec.OrganizationID))
	if err != nil {
		return nil, err
	}

	audit.Record(s.c, &audit.Entry{
		Action:         "admin.refresh_token",
		AdminID:        rec.AccountID,
		OrganizationID: rec.OrganizationID,
		SessionID:      rec.SessionID,
		Success:        true,
	})
	return &auth.AdminLoginResponse{
		Code:                  errno.SuccessCode,
		Message:               errno.SuccessMsg,
		AccessToken:           accessToken,
		RefreshToken:          rec.RefreshToken,
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: rec.ExpiresAt,
	}, nil
}

// AdminLogout ends the admin session by revoking its server-side record. The
// session id is taken from the authenticated token (set by SessionAuth), not
// from the request body, so an admin can only log out their own session. The
// refresh token is deleted immediately and the short-lived access token expires
// on its own shortly after. Revoking a missing session is a no-op.
func (s *AdminAuthService) AdminLogout(req *auth.AdminLogoutRequest) (*auth.AdminLoginResponse, error) {
	sid := s.currentSessionID()
	if sid != "" {
		if err := sessionStore.Revoke(jwt.SubjectAdmin, sid); err != nil {
			return nil, err
		}
	}
	adminID, _ := s.currentAccountID()
	audit.Record(s.c, &audit.Entry{
		Action:    "admin.logout",
		AdminID:   adminID,
		SessionID: sid,
		Success:   true,
	})
	return &auth.AdminLoginResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
	}, nil
}

// ValidateAdminToken verifies an access token's signature and expiry and returns
// the decoded admin auth context. An invalid/expired token is reported as
// Valid=false in the response (not as a Go error) so the handler still answers 200.
func (s *AdminAuthService) ValidateAdminToken(req *auth.ValidateAdminTokenRequest) (*auth.ValidateAdminTokenResponse, error) {
	if req.AccessToken == "" {
		return nil, errno.ParamErr
	}
	claims, err := jwt.ParseAdminToken(req.AccessToken)
	if err != nil {
		return &auth.ValidateAdminTokenResponse{
			Code:    errno.AuthorizationFailedErrCode,
			Message: "token is invalid or expired",
			Valid:   false,
		}, nil
	}

	var expiresAt int64
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time.Unix()
	}
	return &auth.ValidateAdminTokenResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Valid:   true,
		Context: &auth.AdminAuthContext{
			AccountId:      claims.AdminID,
			OrganizationId: claims.OrganizationID,
		},
		ExpiresAt: expiresAt,
	}, nil
}

// SwitchOrganization binds the authenticated admin's platform token to the
// chosen organization, issuing a new access token scoped to it. Membership is
// verified first so an account cannot mint a token for an org it does not belong to.
func (s *AdminAuthService) SwitchOrganization(req *auth.SwitchOrganizationRequest) (*auth.SwitchOrganizationResponse, error) {
	if req.OrganizationId == 0 {
		return nil, errno.ParamErr
	}
	accountID, err := s.currentAccountID()
	if err != nil {
		return nil, err
	}

	membership, err := s.organizationMembershipDAO.QueryMembership(req.OrganizationId, accountID)
	if err != nil {
		audit.Record(s.c, &audit.Entry{
			Action:         "admin.switch_organization",
			AdminID:        accountID,
			OrganizationID: req.OrganizationId,
			SessionID:      s.currentSessionID(),
			Success:        false,
			ErrMsg:         "not a member of target organization",
		})
		return nil, err
	}

	// Keep the switched token on the SAME session so it still passes the
	// JWT+session check; switching org only re-scopes the access token's org.
	// 组织可配置本组织 admin access token 的时长，切换组织后按新组织设置签发。
	accessToken, accessExp, err := jwt.GenerateAdminAccessToken(accountID, req.OrganizationId, s.currentSessionID(), s.adminAccessTTL(req.OrganizationId))
	if err != nil {
		return nil, err
	}

	audit.Record(s.c, &audit.Entry{
		Action:         "admin.switch_organization",
		AdminID:        accountID,
		OrganizationID: req.OrganizationId,
		SessionID:      s.currentSessionID(),
		Success:        true,
	})
	return &auth.SwitchOrganizationResponse{
		Code:                 errno.SuccessCode,
		Message:              errno.SuccessMsg,
		AccessToken:          accessToken,
		AccessTokenExpiresAt: accessExp,
		Context: &auth.AdminAuthContext{
			AccountId:      accountID,
			OrganizationId: req.OrganizationId,
			MembershipId:   membership.ID,
		},
	}, nil
}

// adminAccessTTL 返回指定组织配置的 admin access token 有效时长；
// 组织未配置（orgID 为 0 或查询失败）时回退到全局默认值。
func (s *AdminAuthService) adminAccessTTL(orgID int64) time.Duration {
	return time.Duration(db.AdminAccessTokenTTL(orgID)) * time.Second
}

// currentAccountID reads the authenticated account id set by the JWT middleware.
func (s *AdminAuthService) currentAccountID() (int64, error) {
	v, ok := s.c.Get("current_user_id")
	if !ok {
		return 0, errno.AuthorizationFailedErr
	}
	id, ok := v.(int64)
	if !ok {
		return 0, errno.AuthorizationFailedErr
	}
	return id, nil
}

// currentSessionID reads the session id set by the SessionAuth middleware, or
// "" when absent (e.g. the route is not guarded by SessionAuth).
func (s *AdminAuthService) currentSessionID() string {
	v, ok := s.c.Get("session_id")
	if !ok {
		return ""
	}
	sid, _ := v.(string)
	return sid
}

// auditExtra marshals free-form metadata for an audit Entry.Extra field,
// best-effort. Email is PII but not a secret; never put passwords/tokens here.
func auditExtra(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
