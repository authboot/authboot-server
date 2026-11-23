/*
 * Copyright 2023 CloudWeGo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package user

import (
	"context"
	"errors"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/model/common"
	"github.com/authboot/authboot-server/biz/model/user"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/oauth"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
)

// bindCodeStore is the redis-backed one-time code store for identity binding.
// The scenes ("bind_email" / "bind_mobile") must stay in sync with the message
// service, which is where the client asks the code to be sent.
var bindCodeStore redis.Code

const (
	// wechatProvider is the oauth registry key for 微信 授权登录.
	wechatProvider = "wechat"
	// bindCodeSceneEmail / bindCodeSceneMobile match the message service's
	// BIND_EMAIL / BIND_MOBILE scene keys.
	bindCodeSceneEmail  = "bind_email"
	bindCodeSceneMobile = "bind_mobile"
)

// IdentityService manages the identities bound to the authenticated user:
// bind a new login method (email / phone / wechat), unbind one, and list what
// is bound. The acting user comes from the token, never from the request, so a
// user can only ever modify their own identities.
type IdentityService struct {
	ctx context.Context
	c   *app.RequestContext

	userDAO         *db.UserDAO
	userIdentityDAO identityStore
}

type identityStore interface {
	QueryIdentity(int64, string, string) (*db.UserIdentity, error)
	CreateIdentity(*db.UserIdentity) (int64, error)
	ListIdentitiesByUserInOrg(int64, int64) ([]*db.UserIdentity, error)
	DeleteIdentities(int64, int64, string, string) (int64, error)
}

// NewIdentityService creates an identity self-service.
func NewIdentityService(ctx context.Context, c *app.RequestContext) *IdentityService {
	return &IdentityService{
		ctx:             ctx,
		c:               c,
		userDAO:         db.NewUserDAO(db.DB),
		userIdentityDAO: db.NewUserIdentityDAO(db.DB),
	}
}

// BindIdentity links a login identity to the current account. The credential
// proves ownership of the identity being bound (a code sent to the contact, or
// a fresh OAuth re-authorization). An identity owned by another account conflicts.
func (s *IdentityService) BindIdentity(req *user.BindIdentityRequest) (*user.BindIdentityResponse, error) {
	me, err := s.currentUser()
	if err != nil {
		return nil, err
	}
	identityType := identityTypeToString(req.IdentityType)
	if identityType == "" {
		return nil, errno.ParamErr
	}
	identityValue, err := s.verifyBindCredential(me.OrganizationID, req)
	if err != nil {
		return nil, err
	}
	return s.bind(me, identityType, identityValue)
}

// UnbindIdentity removes a bound identity (optionally one specific value of a
// type). The last remaining login identity can never be unbound, so the account
// is never left without a way to sign in.
func (s *IdentityService) UnbindIdentity(req *user.UnbindIdentityRequest) (*user.UnbindIdentityResponse, error) {
	me, err := s.currentUser()
	if err != nil {
		return nil, err
	}
	identityType := identityTypeToString(req.IdentityType)
	if identityType == "" {
		return nil, errno.ParamErr
	}
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		var locked db.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND organization_id = ?", me.ID, me.OrganizationID).First(&locked).Error; err != nil {
			return err
		}
		if _, err := (redis.SessionStore{}).GetWithDB(tx, jwt.SubjectUser, s.c.GetString(jwt.CtxKeySessionID)); err != nil {
			return errno.AuthorizationFailedErr
		}
		dao := db.NewUserIdentityDAO(tx)
		identities, err := dao.ListIdentitiesByUserInOrg(me.OrganizationID, me.ID)
		if err != nil {
			return err
		}
		removed, remaining := 0, 0
		for _, identity := range identities {
			if identity.IdentityType == identityType && (req.IdentityValue == "" || identity.IdentityValue == req.IdentityValue) {
				removed++
			} else {
				remaining++
			}
		}
		if removed == 0 {
			return nil
		}
		if remaining == 0 {
			return errno.IdentityLastOneErr
		}
		if err := db.ConsumeSecurityGrant(tx, string(s.c.GetHeader("X-Step-Up-Token")), db.SecurityGrant{Subject: jwt.SubjectUser, AccountID: me.ID, OrganizationID: me.OrganizationID, SessionID: s.c.GetString(jwt.CtxKeySessionID), Scope: "identity:unbind"}, time.Now()); err != nil {
			return errno.AuthorizationFailedErr
		}
		_, err = dao.DeleteIdentities(me.OrganizationID, me.ID, identityType, req.IdentityValue)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &user.UnbindIdentityResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
	}, nil
}

// ListMyIdentities returns every login identity bound to the current account.
func (s *IdentityService) ListMyIdentities(req *user.ListMyIdentitiesRequest) (*user.ListMyIdentitiesResponse, error) {
	me, err := s.currentUser()
	if err != nil {
		return nil, err
	}
	identities, err := s.userIdentityDAO.ListIdentitiesByUserInOrg(me.OrganizationID, me.ID)
	if err != nil {
		return nil, err
	}
	infos := make([]*user.UserIdentity, 0, len(identities))
	for _, id := range identities {
		infos = append(infos, toUserIdentityInfo(id))
	}
	return &user.ListMyIdentitiesResponse{
		Code:       errno.SuccessCode,
		Message:    errno.SuccessMsg,
		Identities: infos,
	}, nil
}

// verifyBindCredential proves ownership of the identity being bound. For email
// / phone it verifies a one-time code sent to that contact; for wechat it
// exchanges a fresh OAuth authorization code (re-authorization of the wechat
// account). The returned value is the identity value to bind (the contact for
// email/phone, the openid for wechat).
func (s *IdentityService) verifyBindCredential(org int64, req *user.BindIdentityRequest) (string, error) {
	switch req.IdentityType {
	case common.IdentityType_IDENTITY_TYPE_EMAIL:
		if req.IdentityValue == "" || req.Credential == "" {
			return "", errno.ParamErr
		}
		if !bindCodeStore.Verify(bindCodeSceneEmail, req.IdentityValue, req.Credential) {
			return "", errno.AuthorizationFailedErr
		}
		return req.IdentityValue, nil
	case common.IdentityType_IDENTITY_TYPE_PHONE:
		if req.IdentityValue == "" || req.Credential == "" {
			return "", errno.ParamErr
		}
		if !bindCodeStore.Verify(bindCodeSceneMobile, req.IdentityValue, req.Credential) {
			return "", errno.AuthorizationFailedErr
		}
		return req.IdentityValue, nil
	case common.IdentityType_IDENTITY_TYPE_WECHAT:
		if req.Credential == "" {
			return "", errno.ParamErr
		}
		tok, err := oauth.Exchange(s.ctx, org, wechatProvider, req.Credential)
		if err != nil {
			return "", err
		}
		info, err := oauth.FetchUserInfo(s.ctx, org, wechatProvider, tok)
		if err != nil {
			return "", err
		}
		return info.OpenID, nil
	default:
		return "", errno.ParamErr
	}
}

// bind is the shared tail of BindIdentity: it checks whether the identity is
// already taken and either binds it to the current account, idempotently
// succeeds, or returns an identity conflict.
func (s *IdentityService) bind(me *db.User, identityType, identityValue string) (*user.BindIdentityResponse, error) {
	existing, err := s.userIdentityDAO.QueryIdentity(me.OrganizationID, identityType, identityValue)
	switch {
	case err == nil:
		if existing.UserID == me.ID {
			// Already bound to this account — idempotent success.
			return &user.BindIdentityResponse{
				Code:     errno.SuccessCode,
				Message:  errno.SuccessMsg,
				Identity: toUserIdentityInfo(existing),
			}, nil
		}
		return nil, errno.IdentityAlreadyExistErr
	case errors.Is(err, errno.UserIsNotExistErr):
		now := time.Now().Unix()
		id, err := s.userIdentityDAO.CreateIdentity(&db.UserIdentity{
			OrganizationID: me.OrganizationID,
			UserID:         me.ID,
			IdentityType:   identityType,
			IdentityValue:  identityValue,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
		if err != nil {
			var duplicate *mysql.MySQLError
			if errors.Is(err, gorm.ErrDuplicatedKey) || (errors.As(err, &duplicate) && duplicate.Number == 1062) {
				return nil, errno.IdentityAlreadyExistErr
			}
			return nil, err
		}
		created := &db.UserIdentity{
			ID:             id,
			OrganizationID: me.OrganizationID,
			UserID:         me.ID,
			IdentityType:   identityType,
			IdentityValue:  identityValue,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		return &user.BindIdentityResponse{
			Code:     errno.SuccessCode,
			Message:  errno.SuccessMsg,
			Identity: toUserIdentityInfo(created),
		}, nil
	default:
		return nil, err
	}
}

// currentUser resolves the authenticated user from the token context set by
// jwt.UserSessionAuth.
func (s *IdentityService) currentUser() (*db.User, error) {
	userID, _ := s.c.Get(jwt.CtxKeyUserID)
	id, _ := userID.(int64)
	orgID, _ := s.c.Get(jwt.CtxKeyOrgID)
	oid, _ := orgID.(int64)
	if id == 0 || oid == 0 {
		return nil, errno.AuthorizationFailedErr
	}
	return s.userDAO.QueryUserByIdInOrg(oid, id)
}

// toUserIdentityInfo maps a db identity row to the API model. Bound identities
// are verified by construction (a code or OAuth exchange), so Verified is true.
func toUserIdentityInfo(id *db.UserIdentity) *user.UserIdentity {
	return &user.UserIdentity{
		Id:             id.ID,
		OrganizationId: id.OrganizationID,
		UserId:         id.UserID,
		IdentityType:   identityTypeToProto(id.IdentityType),
		IdentityValue:  id.IdentityValue,
		Verified:       true,
		CreatedAt:      id.CreatedAt,
		UpdatedAt:      id.UpdatedAt,
	}
}

// identityTypeToProto maps a stored identity_type string back to the proto
// enum. Unknown stored values are reported as UNKNOWN.
func identityTypeToProto(t string) common.IdentityType {
	switch t {
	case constants.IdentityTypeEmail:
		return common.IdentityType_IDENTITY_TYPE_EMAIL
	case constants.IdentityTypePhone:
		return common.IdentityType_IDENTITY_TYPE_PHONE
	case constants.IdentityTypeUsername:
		return common.IdentityType_IDENTITY_TYPE_UNKNOWN
	case constants.IdentityTypeWechat:
		return common.IdentityType_IDENTITY_TYPE_WECHAT
	case constants.IdentityTypeUnionID:
		return common.IdentityType_IDENTITY_TYPE_UNKNOWN
	case constants.IdentityTypeApple:
		return common.IdentityType_IDENTITY_TYPE_APPLE
	case constants.IdentityTypeGoogle:
		return common.IdentityType_IDENTITY_TYPE_GOOGLE
	default:
		return common.IdentityType_IDENTITY_TYPE_UNKNOWN
	}
}
