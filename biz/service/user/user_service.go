package user

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/model/common"
	"github.com/authboot/authboot-server/biz/model/user"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
)

// pagination defaults / bounds for ListUsers.
const (
	defaultPage     = 1
	defaultPageSize = 20
	maxPageSize     = 100
)

// UserService handles admin-side management of an organization's end users:
// lookup (by id / identity), listing, profile update, and disable. All methods
// are scoped to an organization so a token for org B can never touch org A.
// UserService handles admin-side management of an organization's end users.
type UserService struct {
	ctx context.Context
	c   *app.RequestContext

	userDAO         *db.UserDAO
	userIdentityDAO *db.UserIdentityDAO
}

// NewUserService creates a user management service.
func NewUserService(ctx context.Context, c *app.RequestContext) *UserService {
	return &UserService{
		ctx: ctx,
		c:   c,

		userDAO:         db.NewUserDAO(db.DB),
		userIdentityDAO: db.NewUserIdentityDAO(db.DB),
	}
}

// GetUser returns a single user by id within an organization.
func (s *UserService) GetUser(req *user.GetUserRequest) (*user.GetUserResponse, error) {
	if req.OrganizationId == 0 || req.UserId == 0 {
		return nil, errno.ParamErr
	}
	u, err := s.userDAO.QueryUserByIdInOrg(req.OrganizationId, req.UserId)
	if err != nil {
		return nil, err
	}
	infos, err := s.buildUserInfo(u)
	if err != nil {
		return nil, err
	}
	return &user.GetUserResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		User:    infos,
	}, nil
}

// GetUserByIdentity resolves the user bound to a login identity (type+value)
// within an organization.
func (s *UserService) GetUserByIdentity(req *user.GetUserByIdentityRequest) (*user.GetUserByIdentityResponse, error) {
	if req.OrganizationId == 0 || req.IdentityValue == "" {
		return nil, errno.ParamErr
	}
	idType := identityTypeToString(req.IdentityType)
	if idType == "" {
		return nil, errno.ParamErr
	}
	identity, err := s.userIdentityDAO.QueryIdentity(req.OrganizationId, idType, req.IdentityValue)
	if err != nil {
		return nil, err
	}
	u, err := s.userDAO.QueryUserByIdInOrg(req.OrganizationId, identity.UserID)
	if err != nil {
		return nil, err
	}
	infos, err := s.buildUserInfo(u)
	if err != nil {
		return nil, err
	}
	return &user.GetUserByIdentityResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		User:    infos,
	}, nil
}

// ListUsers returns a page of users within an organization plus the total count.
func (s *UserService) ListUsers(req *user.ListUsersRequest) (*user.ListUsersResponse, error) {
	if req.OrganizationId == 0 {
		return nil, errno.ParamErr
	}
	page, pageSize := normalizePaging(req.Page, req.PageSize)
	users, total, err := s.userDAO.ListUsersInOrg(req.OrganizationId, (page-1)*pageSize, pageSize)
	if err != nil {
		return nil, err
	}
	infos := make([]*user.User, 0, len(users))
	for _, u := range users {
		info, err := s.buildUserInfo(u)
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return &user.ListUsersResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Users:   infos,
		Total:   total,
	}, nil
}

// UpdateUser updates a user's mutable profile fields. Only non-zero fields on
// the request are applied, leaving the rest untouched.
func (s *UserService) UpdateUser(req *user.UpdateUserRequest) (*user.UpdateUserResponse, error) {
	if req.OrganizationId == 0 || req.UserId == 0 {
		return nil, errno.ParamErr
	}
	u, err := s.userDAO.QueryUserByIdInOrg(req.OrganizationId, req.UserId)
	if err != nil {
		return nil, err
	}
	if req.Nickname != "" {
		u.UserName = req.Nickname
	}
	if req.Avatar != "" {
		u.Avatar = req.Avatar
	}
	if req.Gender != common.Gender_GENDER_UNKNOWN {
		u.Gender = int8(req.Gender)
	}
	if req.Birthday != "" {
		u.Birthday = req.Birthday
	}
	if req.Bio != "" {
		u.Bio = req.Bio
	}
	if err := s.userDAO.UpdateUser(u); err != nil {
		return nil, err
	}
	infos, err := s.buildUserInfo(u)
	if err != nil {
		return nil, err
	}
	return &user.UpdateUserResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		User:    infos,
	}, nil
}

// DisableUser disables a user within an organization.
func (s *UserService) DisableUser(req *user.DisableUserRequest) (*user.DisableUserResponse, error) {
	if req.OrganizationId == 0 || req.UserId == 0 {
		return nil, errno.ParamErr
	}
	if _, err := s.userDAO.QueryUserByIdInOrg(req.OrganizationId, req.UserId); err != nil {
		return nil, err
	}
	if err := s.userDAO.SetUserStatus(req.OrganizationId, req.UserId, constants.StatusDisabled); err != nil {
		return nil, err
	}
	return &user.DisableUserResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
	}, nil
}

// EnableUser re-enables a disabled user within an organization.
func (s *UserService) EnableUser(req *user.EnableUserRequest) (*user.EnableUserResponse, error) {
	if req.OrganizationId == 0 || req.UserId == 0 {
		return nil, errno.ParamErr
	}
	if _, err := s.userDAO.QueryUserByIdInOrg(req.OrganizationId, req.UserId); err != nil {
		return nil, err
	}
	if err := s.userDAO.SetUserStatus(req.OrganizationId, req.UserId, constants.StatusEnabled); err != nil {
		return nil, err
	}
	return &user.EnableUserResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
	}, nil
}

// toUserInfo maps a db user row to the API user model. A zero status (legacy
// rows created before the status column) is reported as ENABLED. Sensitive
// fields (password hash, settings JSON) are deliberately NOT exposed.
func toUserInfo(u *db.User) *user.User {
	status := common.Status(u.Status)
	if status == common.Status_STATUS_UNKNOWN {
		status = common.Status_STATUS_ENABLED
	}
	return &user.User{
		Id:              u.ID,
		OrganizationId:  u.OrganizationID,
		Nickname:        u.UserName,
		Avatar:          u.Avatar,
		Status:          status,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
		Gender:          common.Gender(u.Gender),
		Birthday:        u.Birthday,
		Bio:             u.Bio,
		BackgroundImage: u.BackgroundImage,
		Signature:       u.Signature,
	}
}

// buildUserInfo 在 toUserInfo 基础上回填绑定身份（email / phone）。身份查询
// 失败降级为空值：档案主体已可用，不应因联系信息查询失败整体报错。
func (s *UserService) buildUserInfo(u *db.User) (*user.User, error) {
	info := toUserInfo(u)
	identities, err := s.userIdentityDAO.ListIdentitiesByUserInOrg(u.OrganizationID, u.ID)
	if err != nil {
		hlog.CtxErrorf(s.ctx, "list identities for user %d: %v", u.ID, err)
		return info, nil
	}
	for _, id := range identities {
		switch id.IdentityType {
		case constants.IdentityTypeEmail:
			if info.Email == "" {
				info.Email = id.IdentityValue
			}
		case constants.IdentityTypePhone:
			if info.Phone == "" {
				info.Phone = id.IdentityValue
			}
		}
	}
	return info, nil
}

// GetMyProfile returns the authenticated user's own profile. The user id comes
// from the token context (set by jwt.UserSessionAuth), never from the request.
func (s *UserService) GetMyProfile(req *user.GetMyProfileRequest) (*user.GetMyProfileResponse, error) {
	u, err := s.currentUser()
	if err != nil {
		return nil, err
	}
	return &user.GetMyProfileResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Profile: toUserProfile(u),
	}, nil
}

// UpdateMyProfile updates the authenticated user's mutable profile fields.
// Only non-zero request fields are applied.
func (s *UserService) UpdateMyProfile(req *user.UpdateMyProfileRequest) (*user.UpdateMyProfileResponse, error) {
	u, err := s.currentUser()
	if err != nil {
		return nil, err
	}
	if req.Nickname != "" {
		u.UserName = req.Nickname
	}
	if req.Avatar != "" {
		u.Avatar = req.Avatar
	}
	if req.Gender != common.Gender_GENDER_UNKNOWN {
		u.Gender = int8(req.Gender)
	}
	if req.Birthday != "" {
		u.Birthday = req.Birthday
	}
	if req.Bio != "" {
		u.Bio = req.Bio
	}
	if err := s.userDAO.UpdateUser(u); err != nil {
		return nil, err
	}
	return &user.UpdateMyProfileResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Profile: toUserProfile(u),
	}, nil
}

// currentUser resolves the authenticated user from the token context.
func (s *UserService) currentUser() (*db.User, error) {
	userID, ok := s.c.Get(jwt.CtxKeyUserID)
	if !ok {
		return nil, errno.AuthorizationFailedErr
	}
	id, ok := userID.(int64)
	if !ok || id == 0 {
		return nil, errno.AuthorizationFailedErr
	}
	orgID, ok := s.c.Get(jwt.CtxKeyOrgID)
	if !ok {
		return nil, errno.AuthorizationFailedErr
	}
	oid, ok := orgID.(int64)
	if !ok || oid == 0 {
		return nil, errno.AuthorizationFailedErr
	}
	return s.userDAO.QueryUserByIdInOrg(oid, id)
}

// toUserProfile maps a db user row to the self-service profile view.
func toUserProfile(u *db.User) *user.UserProfile {
	return &user.UserProfile{
		UserId:         u.ID,
		OrganizationId: u.OrganizationID,
		Nickname:       u.UserName,
		Avatar:         u.Avatar,
		Gender:         common.Gender(u.Gender),
		Birthday:       u.Birthday,
		Bio:            u.Bio,
	}
}

// normalizePaging clamps the request's page / page_size into sane bounds,
// falling back to defaults when unset.
func normalizePaging(page, pageSize int32) (int, int) {
	p := int(page)
	if p < 1 {
		p = defaultPage
	}
	ps := int(pageSize)
	if ps < 1 {
		ps = defaultPageSize
	}
	if ps > maxPageSize {
		ps = maxPageSize
	}
	return p, ps
}

// identityTypeToString maps the proto IdentityType enum to the identity_type
// string stored in user_identities. Unsupported types return "".
func identityTypeToString(t common.IdentityType) string {
	switch t {
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
