package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"gorm.io/gorm"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/model/auth"
	"github.com/authboot/authboot-server/biz/model/common"
	"github.com/authboot/authboot-server/biz/model/session"
	"github.com/authboot/authboot-server/biz/model/user"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/oauth"
	"github.com/authboot/authboot-server/biz/mw/redis"
	userservice "github.com/authboot/authboot-server/biz/service/user"
	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/authboot/authboot-server/pkg/utils"
)

// codeStore is the redis-backed one-time verification-code store shared by the
// email / SMS login flows.
var codeStore redis.Code

// sessionStore is the redis-backed server-side session / refresh-token store.
// Login opens a session (opaque refresh token), refresh rotates it, logout
// revokes it — so refresh tokens are revocable, unlike a self-contained JWT.
var sessionStore redis.SessionStore

const (
	// wechatProvider is the oauth registry key for 微信 授权登录.
	wechatProvider = "wechat"
	// codeSceneLogin namespaces verification codes issued for login.
	codeSceneLogin = "login"
	// codeSceneRegister namespaces verification codes issued for registration.
	// Must stay in sync with the message service's REGISTER scene ("register").
	codeSceneRegister = "register"
	// claimCodeSceneEmail / claimCodeSceneMobile are the verification-code scenes
	// used to prove ownership of the claimed contact at login time. They must
	// stay in sync with the message service's BIND_EMAIL / BIND_MOBILE scenes
	// ("bind_email" / "bind_mobile"), which is where the client asks the code to
	// be sent before logging in with claim fields.
	claimCodeSceneEmail  = "bind_email"
	claimCodeSceneMobile = "bind_mobile"
	// codeSceneResetPassword is the message scene used for forgot-password codes.
	codeSceneResetPassword = "reset_password"
	// codeSceneDeleteAccount is the message scene used for account-deletion codes.
	codeSceneDeleteAccount = "delete_account"
	// oauthStateScene is the code-store scene holding one-time OAuth CSRF states
	// issued by the authorize endpoint.
	oauthStateScene = "oauth_state"
	// codeTTL is how long an email / SMS login code stays valid.
	codeTTL = 5 * time.Minute
)

// AuthService handles app-side (end user) authentication: account+password,
// email code, SMS code, and 微信 OAuth login. Admin login lives in
// AdminAuthService.
type AuthService struct {
	ctx context.Context
	c   *app.RequestContext

	userDAO         *db.UserDAO
	userIdentityDAO *db.UserIdentityDAO
	organizationDAO *db.OrganizationDAO
}

// NewAuthService creates an app auth service.
func NewAuthService(ctx context.Context, c *app.RequestContext) *AuthService {
	return &AuthService{
		ctx:             ctx,
		c:               c,
		userDAO:         db.NewUserDAO(db.DB),
		userIdentityDAO: db.NewUserIdentityDAO(db.DB),
		organizationDAO: db.IOrganizationDAO,
	}
}

// Login authenticates an end user and issues an access/refresh token pair. It
// dispatches to the concrete login method:
//
//   - account + password : req.Username + req.Password set
//   - email code         : req.IdentityType == EMAIL,  value=email, credential=code
//   - SMS code           : req.IdentityType == PHONE,  value=phone, credential=code
//   - 微信 OAuth          : req.IdentityType == WECHAT, credential=授权 code
func (s *AuthService) Login(req *auth.LoginRequest) (*auth.LoginResponse, error) {
	u, err := s.authenticate(req)
	if err != nil {
		s.recordLogin(req, 0, err)
		return nil, err
	}
	resp, err := s.buildLoginResponse(u, req.ClientId, req.DeviceId, req.DeviceName)
	if err != nil {
		s.recordLogin(req, u.ID, err)
		return nil, err
	}
	s.recordLogin(req, u.ID, nil)
	// 登记设备（best-effort：首见插入，复登更新 last_used_at / login_count）
	if err := db.UpsertUserDevice(u.OrganizationID, u.ID, req.ClientId, req.DeviceId, req.DeviceName, s.c.ClientIP(), string(s.c.UserAgent()), time.Now().Unix()); err != nil {
		hlog.CtxErrorf(s.ctx, "upsert user device %s: %v", req.DeviceId, err)
	}
	return resp, nil
}

// loginMethod 描述一次登录/注册请求使用的登录方式，用于对照组织设置中的开关。
// 除了三个固定开关外，其余值一律视为 OAuth 提供商名（如 wechat/google/apple/
// github/alipay），按组织设置中的 oauth_providers 允许列表校验。
type loginMethod string

const (
	loginMethodEmailPassword loginMethod = "email_password" // 邮箱/账号 + 密码
	loginMethodEmailCode     loginMethod = "email_code"     // 邮箱验证码
	loginMethodPhoneCode     loginMethod = "phone_code"     // 手机验证码
)

// checkLoginMethodAllowed 校验组织设置是否允许该登录方式。OAuth 提供商同样
// 经由此函数校验（method 为非固定开关值时查 oauth_providers 列表）。
// 组织不存在或配置读取失败时放行（保持与引入设置前一致，登录路径不应因
// 配置故障而整体不可用）。
func (s *AuthService) checkLoginMethodAllowed(orgID int64, method loginMethod) error {
	if orgID <= 0 {
		return nil
	}
	settings, err := s.organizationDAO.GetOrganizationSettings(orgID)
	if err != nil {
		hlog.CtxErrorf(s.ctx, "load org %d settings for login gate: %v", orgID, err)
		return nil
	}
	lm := settings.LoginMethods
	if lm == nil {
		return nil
	}
	switch method {
	case loginMethodEmailPassword:
		if !lm.EmailPassword {
			return errno.LoginMethodDisabledErr
		}
	case loginMethodEmailCode:
		if !lm.EmailCode {
			return errno.LoginMethodDisabledErr
		}
	case loginMethodPhoneCode:
		if !lm.PhoneCode {
			return errno.LoginMethodDisabledErr
		}
	default:
		// 非固定开关的值即 OAuth 提供商名：不在允许列表内则拒绝
		for _, p := range lm.OAuthProviders {
			if p == string(method) {
				return nil
			}
		}
		return errno.LoginMethodDisabledErr
	}
	return nil
}

// authenticate dispatches to the concrete login method and applies
// claim-at-login, returning the authenticated user.
func (s *AuthService) authenticate(req *auth.LoginRequest) (*db.User, error) {
	var u *db.User
	var err error
	// 账号密码登录：显式带上 username+password 即走此分支。
	if req.Username != "" && req.Password != "" {
		if err := s.checkLoginMethodAllowed(req.OrganizationId, loginMethodEmailPassword); err != nil {
			return nil, err
		}
		u, err = s.loginByPassword(req)
	} else {
		switch req.IdentityType {
		case common.IdentityType_IDENTITY_TYPE_EMAIL:
			if err := s.checkLoginMethodAllowed(req.OrganizationId, loginMethodEmailCode); err != nil {
				return nil, err
			}
			u, err = s.loginByEmailCode(req)
		case common.IdentityType_IDENTITY_TYPE_PHONE:
			if err := s.checkLoginMethodAllowed(req.OrganizationId, loginMethodPhoneCode); err != nil {
				return nil, err
			}
			u, err = s.loginBySmsCode(req)
		case common.IdentityType_IDENTITY_TYPE_WECHAT:
			if err := s.checkLoginMethodAllowed(req.OrganizationId, loginMethod(wechatProvider)); err != nil {
				return nil, err
			}
			u, err = s.loginByWechat(req)
		default:
			return nil, errno.ParamErr
		}
	}
	if err != nil {
		return nil, err
	}

	// Claim-at-login: 主登录通过后，若请求携带认领字段，把"另一个身份"所属的
	// 账号并入当前登录账号。业界推荐以邮箱/手机为合并键在登录时认领而非事后
	// 合并，且必须用户主动确认（confirm_claim）+ 双向验证（主登录凭证 + 认领凭证）。
	if err := s.applyClaim(req, u); err != nil {
		return nil, err
	}
	return u, nil
}

// recordLogin appends one append-only login-log row describing the outcome of a
// login request (success, or the failing error with a 0 user id). The identity
// value is stored masked so login history is not a raw PII dump. Best-effort: a
// DB failure is logged, never surfaced to the client — logging must not break
// the login path.
func (s *AuthService) recordLogin(req *auth.LoginRequest, userID int64, loginErr error) {
	log := &db.UserLoginLog{
		OrganizationID: req.OrganizationId,
		UserID:         userID,
		IdentityType:   loginIdentityType(req),
		IdentityValue:  maskIdentityValue(loginIdentityValue(req)),
		ClientID:       req.ClientId,
		DeviceID:       req.DeviceId,
		DeviceName:     req.DeviceName,
		IP:             s.c.ClientIP(),
		UserAgent:      string(s.c.UserAgent()),
		Success:        loginErr == nil,
		CreatedAt:      time.Now().Unix(),
	}
	if loginErr != nil {
		log.ErrMsg = loginErr.Error()
	}
	if err := db.InsertUserLoginLog(log); err != nil {
		hlog.CtxErrorf(s.ctx, "record login log: %v", err)
	}
}

// loginIdentityType maps the login request to the stored identity_type string.
func loginIdentityType(req *auth.LoginRequest) string {
	if req.Username != "" {
		return constants.IdentityTypeUsername
	}
	switch req.IdentityType {
	case common.IdentityType_IDENTITY_TYPE_EMAIL:
		return constants.IdentityTypeEmail
	case common.IdentityType_IDENTITY_TYPE_PHONE:
		return constants.IdentityTypePhone
	case common.IdentityType_IDENTITY_TYPE_WECHAT:
		return constants.IdentityTypeWechat
	default:
		return ""
	}
}

// loginIdentityValue is the credential identifier presented for login (the
// username, or the email/phone/... identity value).
func loginIdentityValue(req *auth.LoginRequest) string {
	if req.Username != "" {
		return req.Username
	}
	return req.IdentityValue
}

// maskIdentityValue hides the middle of an email local-part or phone number
// (e.g. al***@x.com, 138****1234) while keeping enough to identify the account.
func maskIdentityValue(v string) string {
	if v == "" {
		return ""
	}
	if i := strings.Index(v, "@"); i > 0 {
		local, domain := v[:i], v[i:]
		if len(local) <= 2 {
			return strings.Repeat("*", len(local)) + domain
		}
		return local[:2] + strings.Repeat("*", len(local)-2) + domain
	}
	r := []rune(v)
	n := len(r)
	if n <= 4 {
		return strings.Repeat("*", n)
	}
	return string(r[:3]) + strings.Repeat("*", n-3)
}

// loginByPassword resolves the "username" identity and verifies the bcrypt
// password hash stored on the user.
func (s *AuthService) loginByPassword(req *auth.LoginRequest) (*db.User, error) {
	u, err := s.resolveUser(req.OrganizationId, constants.IdentityTypeUsername, req.Username)
	if err != nil {
		return nil, err
	}
	if !utils.VerifyPassword(req.Password, u.Password) {
		return nil, errno.PasswordIsNotVerified
	}
	return u, nil
}

// loginByEmailCode verifies a one-time code sent to the email, then logs in the
// user bound to that email identity.
func (s *AuthService) loginByEmailCode(req *auth.LoginRequest) (*db.User, error) {
	if req.IdentityValue == "" || req.Credential == "" {
		return nil, errno.ParamErr
	}
	if !codeStore.Verify(codeSceneLogin, req.IdentityValue, req.Credential) {
		return nil, errno.AuthorizationFailedErr
	}
	return s.resolveUser(req.OrganizationId, constants.IdentityTypeEmail, req.IdentityValue)
}

// loginBySmsCode verifies a one-time code sent to the phone, then logs in the
// user bound to that phone identity.
func (s *AuthService) loginBySmsCode(req *auth.LoginRequest) (*db.User, error) {
	if req.IdentityValue == "" || req.Credential == "" {
		return nil, errno.ParamErr
	}
	if !codeStore.Verify(codeSceneLogin, req.IdentityValue, req.Credential) {
		return nil, errno.AuthorizationFailedErr
	}
	return s.resolveUser(req.OrganizationId, constants.IdentityTypePhone, req.IdentityValue)
}

// loginByWechat completes the 微信 OAuth2 authorization-code flow: it exchanges
// the code for a token, fetches the openid/profile, and logs in the matching
// user — auto-provisioning one on first login so a new 微信 user can sign in
// without a separate registration step.
func (s *AuthService) loginByWechat(req *auth.LoginRequest) (*db.User, error) {
	if req.Credential == "" {
		return nil, errno.ParamErr
	}
	tok, err := oauth.Exchange(s.ctx, req.OrganizationId, wechatProvider, req.Credential)
	if err != nil {
		return nil, err
	}
	info, err := oauth.FetchUserInfo(s.ctx, req.OrganizationId, wechatProvider, tok)
	if err != nil {
		return nil, err
	}

	u, err := s.resolveUser(req.OrganizationId, constants.IdentityTypeWechat, info.OpenID)
	switch {
	case err == nil:
		// 已绑定，直接登录。
	case errors.Is(err, errno.UserIsNotExistErr):
		// 首次 微信 登录：自动创建用户并绑定 openid 身份。
		u, err = s.createUserWithIdentity(req.OrganizationId, constants.IdentityTypeWechat, info.OpenID, info.Nickname, info.AvatarURL, "")
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return u, nil
}

// Register creates a new app user with the given identity and logs it in,
// returning the same token-bearing response as Login (RegisterResponse aliases
// LoginResponse). It dispatches on IdentityType because req.Credential is a
// polymorphic credential — NOT always a password:
//
//   - UNKNOWN : username registration, Credential == 账号密码 (bcrypt-hashed & stored)
//   - EMAIL   : Credential == 邮箱验证码 (verified, not stored)
//   - PHONE   : Credential == 短信验证码 (verified, not stored)
//   - WECHAT  : Credential == 微信授权 code (exchanged for openid, not stored)
func (s *AuthService) Register(req *auth.RegisterRequest) (*auth.LoginResponse, error) {
	switch req.IdentityType {
	case common.IdentityType_IDENTITY_TYPE_UNKNOWN:
		if err := s.checkLoginMethodAllowed(req.OrganizationId, loginMethodEmailPassword); err != nil {
			return nil, err
		}
		return s.registerByPassword(req)
	case common.IdentityType_IDENTITY_TYPE_EMAIL:
		if err := s.checkLoginMethodAllowed(req.OrganizationId, loginMethodEmailCode); err != nil {
			return nil, err
		}
		return s.registerByEmailCode(req)
	case common.IdentityType_IDENTITY_TYPE_PHONE:
		if err := s.checkLoginMethodAllowed(req.OrganizationId, loginMethodPhoneCode); err != nil {
			return nil, err
		}
		return s.registerBySmsCode(req)
	case common.IdentityType_IDENTITY_TYPE_WECHAT:
		if err := s.checkLoginMethodAllowed(req.OrganizationId, loginMethod(wechatProvider)); err != nil {
			return nil, err
		}
		return s.registerByWechat(req)
	default:
		return nil, errno.ParamErr
	}
}

// registerByPassword registers a "username" identity whose Credential is the
// account password. This is the only register flow where Credential means a
// password: it is bcrypt-hashed and stored on the user.
func (s *AuthService) registerByPassword(req *auth.RegisterRequest) (*auth.LoginResponse, error) {
	if req.IdentityValue == "" || req.Credential == "" {
		return nil, errno.ParamErr
	}
	passwordHash, err := utils.Crypt(req.Credential)
	if err != nil {
		return nil, err
	}
	return s.finishRegister(req, constants.IdentityTypeUsername, req.IdentityValue, req.Nickname, req.Avatar, passwordHash)
}

// registerByEmailCode registers an email identity after verifying the one-time
// code issued for the register scene. Credential is that code — no password is
// stored.
func (s *AuthService) registerByEmailCode(req *auth.RegisterRequest) (*auth.LoginResponse, error) {
	if req.IdentityValue == "" || req.Credential == "" {
		return nil, errno.ParamErr
	}
	if !codeStore.Verify(codeSceneRegister, req.IdentityValue, req.Credential) {
		return nil, errno.AuthorizationFailedErr
	}
	return s.finishRegister(req, constants.IdentityTypeEmail, req.IdentityValue, req.Nickname, req.Avatar, "")
}

// registerBySmsCode registers a phone identity after verifying the one-time
// code issued for the register scene. Credential is that code — no password is
// stored.
func (s *AuthService) registerBySmsCode(req *auth.RegisterRequest) (*auth.LoginResponse, error) {
	if req.IdentityValue == "" || req.Credential == "" {
		return nil, errno.ParamErr
	}
	if !codeStore.Verify(codeSceneRegister, req.IdentityValue, req.Credential) {
		return nil, errno.AuthorizationFailedErr
	}
	return s.finishRegister(req, constants.IdentityTypePhone, req.IdentityValue, req.Nickname, req.Avatar, "")
}

// registerByWechat registers a 微信 identity: Credential is the OAuth
// authorization code, exchanged for the user's openid/profile. The bound
// identity value is the openid 微信 returns, not req.IdentityValue, and the
// nickname/avatar fall back to the 微信 profile when the client omits them.
func (s *AuthService) registerByWechat(req *auth.RegisterRequest) (*auth.LoginResponse, error) {
	if req.Credential == "" {
		return nil, errno.ParamErr
	}
	tok, err := oauth.Exchange(s.ctx, req.OrganizationId, wechatProvider, req.Credential)
	if err != nil {
		return nil, err
	}
	info, err := oauth.FetchUserInfo(s.ctx, req.OrganizationId, wechatProvider, tok)
	if err != nil {
		return nil, err
	}
	nickname := req.Nickname
	if nickname == "" {
		nickname = info.Nickname
	}
	avatar := req.Avatar
	if avatar == "" {
		avatar = info.AvatarURL
	}
	return s.finishRegister(req, constants.IdentityTypeWechat, info.OpenID, nickname, avatar, "")
}

// finishRegister is the shared tail of every register flow: it rejects a
// duplicate identity, creates the user + identity binding, and issues a login
// response. passwordHash is empty for every non-password identity.
func (s *AuthService) finishRegister(req *auth.RegisterRequest, identityType, identityValue, nickname, avatar, passwordHash string) (*auth.LoginResponse, error) {
	exist, err := s.userIdentityDAO.CheckIdentityExist(req.OrganizationId, identityType, identityValue)
	if err != nil {
		return nil, err
	}
	if exist {
		return nil, errno.IdentityAlreadyExistErr
	}
	u, err := s.createUserWithIdentity(req.OrganizationId, identityType, identityValue, nickname, avatar, passwordHash)
	if err != nil {
		return nil, err
	}
	return s.buildLoginResponse(u, req.ClientId, req.DeviceId, req.DeviceName)
}

// RefreshToken validates and rotates a refresh token: the presented opaque
// refresh token is swapped for a new one on the same session, and a fresh
// short-lived access token is issued. A replayed / unknown token is rejected.
func (s *AuthService) RefreshToken(req *auth.RefreshTokenRequest) (*auth.LoginResponse, error) {
	if req.RefreshToken == "" {
		return nil, errno.ParamErr
	}
	rec, err := sessionStore.Rotate(jwt.SubjectUser, req.RefreshToken, redis.DefaultSessionTTL)
	if err != nil {
		if errors.Is(err, redis.ErrSessionNotFound) {
			return nil, errno.AuthorizationFailedErr
		}
		return nil, err
	}
	u, err := s.userDAO.QueryUserByIdInOrg(rec.OrganizationID, rec.AccountID)
	if err != nil {
		return nil, err
	}
	accessToken, accessExp, err := jwt.GenerateUserAccessToken(rec.AccountID, rec.OrganizationID, rec.SessionID)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	return &auth.LoginResponse{
		Code:                  errno.SuccessCode,
		Message:               errno.SuccessMsg,
		User:                  toUserInfo(u),
		AccessToken:           accessToken,
		RefreshToken:          rec.RefreshToken,
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: rec.ExpiresAt,
		Session: &session.Session{
			SessionId:      rec.SessionID,
			OrganizationId: rec.OrganizationID,
			UserId:         rec.AccountID,
			DeviceId:       rec.DeviceID,
			DeviceName:     rec.DeviceName,
			Status:         session.SessionStatus_SESSION_STATUS_ACTIVE,
			CreatedAt:      rec.CreatedAt,
			ExpiresAt:      accessExp,
			LastActiveAt:   now,
		},
	}, nil
}

// Logout ends the current session by revoking its server-side record: the
// refresh token is deleted immediately, and the short-lived access token
// expires on its own shortly after. Revoking a missing session is a no-op.
func (s *AuthService) Logout(req *auth.LogoutRequest) (*auth.LogoutResponse, error) {
	if req.SessionId != "" {
		if err := sessionStore.Revoke(jwt.SubjectUser, req.SessionId); err != nil {
			return nil, err
		}
	}
	return &auth.LogoutResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
	}, nil
}

// ValidateToken verifies an access token's signature and expiry and returns the
// decoded auth context. An invalid/expired token is reported as Valid=false in
// the response (not as a Go error) so the handler still answers 200.
func (s *AuthService) ValidateToken(req *auth.ValidateTokenRequest) (*auth.ValidateTokenResponse, error) {
	if req.AccessToken == "" {
		return nil, errno.ParamErr
	}
	claims, err := jwt.ParseUserToken(req.AccessToken)
	if err != nil {
		return &auth.ValidateTokenResponse{
			Code:    errno.AuthorizationFailedErrCode,
			Message: "token is invalid or expired",
			Valid:   false,
		}, nil
	}

	var expiresAt int64
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time.Unix()
	}
	return &auth.ValidateTokenResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Valid:   true,
		Context: &auth.AuthContext{
			UserId:         claims.UserID,
			OrganizationId: claims.OrganizationID,
		},
		ExpiresAt: expiresAt,
	}, nil
}

// claimRequested reports whether the login request carries claim-at-login
// fields (a non-empty claim credential or a claim identity type).
func claimRequested(req *auth.LoginRequest) bool {
	return req.ClaimCredential != "" || req.ClaimIdentityType != common.IdentityType_IDENTITY_TYPE_UNKNOWN
}

// applyClaim merges the account proven by the claim credentials into the login
// account. The claim is only applied when the user explicitly confirmed it
// (confirm_claim). Together with the primary login credential, the claim
// credential forms the two-way ownership proof the industry requires: the login
// proves control of the login account, and the claim credential (a contact
// code, or a fresh OAuth re-authorization) proves control of the claimed one.
func (s *AuthService) applyClaim(req *auth.LoginRequest, loginUser *db.User) error {
	if !claimRequested(req) {
		return nil
	}
	if !req.ConfirmClaim {
		return errno.AccountMergeConfirmRequiredErr
	}
	claimed, err := s.resolveClaimedUser(req)
	if err != nil {
		return err
	}
	if claimed.ID == loginUser.ID {
		return nil // already the same account — nothing to merge
	}
	if err := userservice.MergeUserAccounts(s.ctx, loginUser, claimed); err != nil {
		return err
	}
	s.recordUserAudit(loginUser, "user.account.merge", "account", strconv.FormatInt(claimed.ID, 10), true, "")
	return nil
}

// resolveClaimedUser proves ownership of the claimed identity and resolves the
// account bound to it. The claim credential is one-time and consumed on verify:
//   - email / phone: a verification code sent to that contact (bind scene), so
//     only the contact's owner can complete the claim;
//   - wechat: a fresh OAuth authorization code, i.e. re-authorizing the wechat
//     account being claimed.
func (s *AuthService) resolveClaimedUser(req *auth.LoginRequest) (*db.User, error) {
	switch req.ClaimIdentityType {
	case common.IdentityType_IDENTITY_TYPE_EMAIL:
		if req.ClaimIdentityValue == "" || req.ClaimCredential == "" {
			return nil, errno.ParamErr
		}
		if !codeStore.Verify(claimCodeSceneEmail, req.ClaimIdentityValue, req.ClaimCredential) {
			return nil, errno.AuthorizationFailedErr
		}
		return s.resolveUser(req.OrganizationId, constants.IdentityTypeEmail, req.ClaimIdentityValue)
	case common.IdentityType_IDENTITY_TYPE_PHONE:
		if req.ClaimIdentityValue == "" || req.ClaimCredential == "" {
			return nil, errno.ParamErr
		}
		if !codeStore.Verify(claimCodeSceneMobile, req.ClaimIdentityValue, req.ClaimCredential) {
			return nil, errno.AuthorizationFailedErr
		}
		return s.resolveUser(req.OrganizationId, constants.IdentityTypePhone, req.ClaimIdentityValue)
	case common.IdentityType_IDENTITY_TYPE_WECHAT:
		if req.ClaimCredential == "" {
			return nil, errno.ParamErr
		}
		// 组织未开启该提供商时，同样不允许通过它完成认领合并
		if err := s.checkLoginMethodAllowed(req.OrganizationId, loginMethod(wechatProvider)); err != nil {
			return nil, err
		}
		// 重新授权：一次全新的微信授权码 = 重新证明对微信账号的掌控。
		tok, err := oauth.Exchange(s.ctx, req.OrganizationId, wechatProvider, req.ClaimCredential)
		if err != nil {
			return nil, err
		}
		info, err := oauth.FetchUserInfo(s.ctx, req.OrganizationId, wechatProvider, tok)
		if err != nil {
			return nil, err
		}
		return s.resolveUser(req.OrganizationId, constants.IdentityTypeWechat, info.OpenID)
	default:
		return nil, errno.ParamErr
	}
}

// OAuthLogin completes a provider authorization-code flow: it consumes the CSRF
// state issued by the authorize endpoint, exchanges the code, fetches the
// provider profile, resolves (or auto-provisions) the user bound to that
// provider identity, and issues the standard login response.
func (s *AuthService) OAuthLogin(orgID int64, providerName, code, state string, clientID int64, deviceID, deviceName string) (*auth.LoginResponse, error) {
	if orgID == 0 || code == "" || state == "" {
		return nil, errno.ParamErr
	}
	// 组织设置中未开启该提供商时拒绝授权登录
	if err := s.checkLoginMethodAllowed(orgID, loginMethod(providerName)); err != nil {
		return nil, err
	}
	if !codeStore.Verify(oauthStateScene, state, "1") {
		return nil, errno.AuthorizationFailedErr
	}
	identityType, ok := oauthIdentityType(providerName)
	if !ok {
		return nil, errno.ParamErr
	}
	tok, err := oauth.Exchange(s.ctx, orgID, providerName, code)
	if err != nil {
		return nil, err
	}
	info, err := oauth.FetchUserInfo(s.ctx, orgID, providerName, tok)
	if err != nil {
		return nil, err
	}
	u, err := s.resolveUser(orgID, identityType, info.OpenID)
	switch {
	case err == nil:
		// Already bound — log in.
	case errors.Is(err, errno.UserIsNotExistErr):
		// First login with this provider — auto-provision a user.
		u, err = s.createUserWithIdentity(orgID, identityType, info.OpenID, info.Nickname, info.AvatarURL, "")
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return s.buildLoginResponse(u, clientID, deviceID, deviceName)
}

// oauthIdentityType maps a provider name to the stored identity type. Extend
// this switch together with oauth buildProviderFromConfig to add a provider.
func oauthIdentityType(providerName string) (string, bool) {
	switch providerName {
	case wechatProvider:
		return constants.IdentityTypeWechat, true
	default:
		return "", false
	}
}

// recordUserAudit 把用户敏感操作写入 tb_user_audit_logs（best-effort：失败只记
// 日志，不影响主流程）。detail 为已脱敏的 JSON 快照（不含密码/令牌）。
func (s *AuthService) recordUserAudit(u *db.User, action, resourceType, resourceID string, success bool, errMsg string) {
	log := &db.UserAuditLog{
		OrganizationID: u.OrganizationID,
		UserID:         u.ID,
		Action:         action,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		IP:             s.c.ClientIP(),
		UserAgent:      string(s.c.UserAgent()),
		Success:        success,
		ErrMsg:         errMsg,
	}
	if err := db.InsertUserAuditLog(log); err != nil {
		hlog.CtxErrorf(s.ctx, "record user audit %s for user %d: %v", action, u.ID, err)
	}
}

// ChangePassword updates the authenticated user's password. When a password is
// already set the old one must match; accounts created via OAuth / code only
// have no password and must use ResetPassword instead.
func (s *AuthService) ChangePassword(req *auth.ChangePasswordRequest) (*auth.ChangePasswordResponse, error) {
	if req.NewPassword == "" {
		return nil, errno.ParamErr
	}
	u, err := s.currentUser()
	if err != nil {
		return nil, err
	}
	if u.Password == "" {
		return nil, errno.PasswordNotSetErr
	}
	if !utils.VerifyPassword(req.OldPassword, u.Password) {
		s.recordUserAudit(u, "user.password.change", "password", "", false, "old password mismatch")
		return nil, errno.PasswordIsNotVerified
	}
	hash, err := utils.Crypt(req.NewPassword)
	if err != nil {
		return nil, err
	}
	if err := s.userDAO.UpdatePassword(u.OrganizationID, u.ID, hash); err != nil {
		return nil, err
	}
	s.recordUserAudit(u, "user.password.change", "password", "", true, "")
	return &auth.ChangePasswordResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}, nil
}

// ResetPassword (forgot password) verifies a reset-password code sent to a bound
// email/phone and replaces the account password. Every existing session is
// revoked afterwards, so a compromised account is signed out everywhere.
func (s *AuthService) ResetPassword(req *auth.ResetPasswordRequest) (*auth.ResetPasswordResponse, error) {
	if req.OrganizationId == 0 || req.IdentityValue == "" || req.Credential == "" || req.NewPassword == "" {
		return nil, errno.ParamErr
	}
	identityType := identityTypeOf(req.IdentityType)
	if identityType == "" {
		return nil, errno.ParamErr
	}
	// 组织关闭对应登录方式时，也不允许通过该渠道找回密码
	method := loginMethodEmailCode
	if identityType == constants.IdentityTypePhone {
		method = loginMethodPhoneCode
	}
	if err := s.checkLoginMethodAllowed(req.OrganizationId, method); err != nil {
		return nil, err
	}
	if !codeStore.Verify(codeSceneResetPassword, req.IdentityValue, req.Credential) {
		return nil, errno.AuthorizationFailedErr
	}
	u, err := s.resolveUser(req.OrganizationId, identityType, req.IdentityValue)
	if err != nil {
		return nil, err
	}
	hash, err := utils.Crypt(req.NewPassword)
	if err != nil {
		return nil, err
	}
	if err := s.userDAO.UpdatePassword(u.OrganizationID, u.ID, hash); err != nil {
		return nil, err
	}
	// Password reset invalidates every device (best-effort: the reset itself
	// already committed, and session guards fail closed if redis is down).
	if err := sessionStore.RevokeAllForUser(jwt.SubjectUser, u.ID); err != nil {
		hlog.CtxErrorf(s.ctx, "reset password: revoke user %d sessions: %v", u.ID, err)
	}
	s.recordUserAudit(u, "user.password.reset", "password", "", true, "")
	return &auth.ResetPasswordResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}, nil
}

// DeleteAccount (注销) proves ownership with the account password or a
// delete-account code sent to a bound contact, then anonymizes and disables the
// user row and deletes its login identities, addresses and notifications in one
// transaction. The row is kept (not hard-deleted) for referential integrity;
// with no identities left the account can never be signed into again.
func (s *AuthService) DeleteAccount(req *auth.DeleteAccountRequest) (*auth.DeleteAccountResponse, error) {
	u, err := s.currentUser()
	if err != nil {
		return nil, err
	}
	if !s.verifyDeleteOwnership(u, req) {
		return nil, errno.AuthorizationFailedErr
	}
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("organization_id = ? AND user_id = ?", u.OrganizationID, u.ID).
			Delete(&db.UserIdentity{}).Error; err != nil {
			return err
		}
		if err := tx.Where("organization_id = ? AND user_id = ?", u.OrganizationID, u.ID).
			Delete(&db.UserAddress{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", u.ID).
			Delete(&db.Notification{}).Error; err != nil {
			return err
		}
		return tx.Model(&db.User{}).
			Where("id = ? AND organization_id = ?", u.ID, u.OrganizationID).
			Updates(map[string]interface{}{
				"user_name":        fmt.Sprintf("deleted_%d", u.ID),
				"password":         "",
				"avatar":           "",
				"background_image": "",
				"signature":        "",
				"bio":              "",
				"birthday":         "",
				"gender":           int8(0),
				"status":           constants.StatusDisabled,
			}).Error
	})
	if err != nil {
		return nil, err
	}
	if err := sessionStore.RevokeAllForUser(jwt.SubjectUser, u.ID); err != nil {
		hlog.CtxErrorf(s.ctx, "delete account: revoke user %d sessions: %v", u.ID, err)
	}
	s.recordUserAudit(u, "user.account.delete", "account", strconv.FormatInt(u.ID, 10), true, "")
	return &auth.DeleteAccountResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}, nil
}

// verifyDeleteOwnership accepts either the account password or a one-time code
// that must be bound to THIS user's identity.
func (s *AuthService) verifyDeleteOwnership(u *db.User, req *auth.DeleteAccountRequest) bool {
	if req.Password != "" && u.Password != "" && utils.VerifyPassword(req.Password, u.Password) {
		return true
	}
	if req.Credential == "" || req.IdentityValue == "" {
		return false
	}
	identityType := identityTypeOf(req.IdentityType)
	if identityType == "" {
		return false
	}
	identity, err := s.userIdentityDAO.QueryIdentity(u.OrganizationID, identityType, req.IdentityValue)
	if err != nil || identity.UserID != u.ID {
		return false
	}
	return codeStore.Verify(codeSceneDeleteAccount, req.IdentityValue, req.Credential)
}

// identityTypeOf maps a proto IdentityType to the stored identity_type string.
// Password flows only support contact identities (email / phone).
func identityTypeOf(t common.IdentityType) string {
	switch t {
	case common.IdentityType_IDENTITY_TYPE_EMAIL:
		return constants.IdentityTypeEmail
	case common.IdentityType_IDENTITY_TYPE_PHONE:
		return constants.IdentityTypePhone
	default:
		return ""
	}
}

// currentUser resolves the authenticated user from the token context set by
// jwt.UserSessionAuth.
func (s *AuthService) currentUser() (*db.User, error) {
	v, ok := s.c.Get(jwt.CtxKeyUserID)
	if !ok {
		return nil, errno.AuthorizationFailedErr
	}
	id, ok := v.(int64)
	if !ok || id == 0 {
		return nil, errno.AuthorizationFailedErr
	}
	org, ok := s.c.Get(jwt.CtxKeyOrgID)
	if !ok {
		return nil, errno.AuthorizationFailedErr
	}
	oid, _ := org.(int64)
	return s.userDAO.QueryUserByIdInOrg(oid, id)
}

// resolveUser looks up the user bound to an identity within an organization.
func (s *AuthService) resolveUser(organizationID int64, identityType, identityValue string) (*db.User, error) {
	identity, err := s.userIdentityDAO.QueryIdentity(organizationID, identityType, identityValue)
	if err != nil {
		return nil, err
	}
	return s.userDAO.QueryUserByIdInOrg(organizationID, identity.UserID)
}

// createUserWithIdentity creates a new user and binds the given identity to it,
// used for 微信 first-login auto-provisioning. passwordHash may be empty for
// OAuth identities that carry no password.
func (s *AuthService) createUserWithIdentity(organizationID int64, identityType, identityValue, nickname, avatar, passwordHash string) (*db.User, error) {
	u := &db.User{
		OrganizationID: organizationID,
		UserName:       nickname,
		Avatar:         avatar,
		Password:       passwordHash,
	}
	userID, err := s.userDAO.CreateUser(u)
	if err != nil {
		return nil, err
	}
	u.ID = userID

	now := time.Now().Unix()
	if _, err := s.userIdentityDAO.CreateIdentity(&db.UserIdentity{
		OrganizationID: organizationID,
		UserID:         userID,
		IdentityType:   identityType,
		IdentityValue:  identityValue,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		return nil, err
	}
	return u, nil
}

// buildLoginResponse opens a server-side session (minting an opaque, revocable
// refresh token), signs a short-lived access token bound to that session, and
// assembles the login response with a session descriptor for the current device.
func (s *AuthService) buildLoginResponse(u *db.User, clientID int64, deviceID, deviceName string) (*auth.LoginResponse, error) {
	rec, err := sessionStore.Create(jwt.SubjectUser, u.ID, u.OrganizationID, deviceID, deviceName, redis.DefaultSessionTTL)
	if err != nil {
		return nil, err
	}
	accessToken, accessExp, err := jwt.GenerateUserAccessToken(rec.AccountID, rec.OrganizationID, rec.SessionID)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	return &auth.LoginResponse{
		Code:                  errno.SuccessCode,
		Message:               errno.SuccessMsg,
		User:                  toUserInfo(u),
		AccessToken:           accessToken,
		RefreshToken:          rec.RefreshToken,
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: rec.ExpiresAt,
		Session: &session.Session{
			SessionId:      rec.SessionID,
			OrganizationId: u.OrganizationID,
			UserId:         u.ID,
			ClientId:       clientID,
			DeviceId:       deviceID,
			DeviceName:     deviceName,
			Status:         session.SessionStatus_SESSION_STATUS_ACTIVE,
			CreatedAt:      now,
			ExpiresAt:      accessExp,
			LastActiveAt:   now,
		},
	}, nil
}

// toUserInfo maps a db user row to the API user model.
func toUserInfo(u *db.User) *user.User {
	return &user.User{
		Id:             u.ID,
		OrganizationId: u.OrganizationID,
		Nickname:       u.UserName,
		Avatar:         u.Avatar,
		Status:         common.Status_STATUS_ENABLED,
	}
}

// identityTypeToString maps the proto IdentityType enum to the identity_type
// string stored in user_identities. IdentityType UNKNOWN maps to "username"
// (account+password registration). Unsupported types return "".
func identityTypeToString(t common.IdentityType) string {
	switch t {
	case common.IdentityType_IDENTITY_TYPE_UNKNOWN:
		return constants.IdentityTypeUsername
	case common.IdentityType_IDENTITY_TYPE_EMAIL:
		return constants.IdentityTypeEmail
	case common.IdentityType_IDENTITY_TYPE_PHONE:
		return constants.IdentityTypePhone
	case common.IdentityType_IDENTITY_TYPE_WECHAT:
		return constants.IdentityTypeWechat
	case common.IdentityType_IDENTITY_TYPE_GOOGLE:
		return constants.IdentityTypeGoogle
	case common.IdentityType_IDENTITY_TYPE_APPLE:
		return constants.IdentityTypeApple
	default:
		return ""
	}
}

// newVerificationCode returns a cryptographically random 6-digit code.
func newVerificationCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
