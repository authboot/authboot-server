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

// Package internalapi implements the service-to-service API surface (token
// introspection and user lookup). Every route is guarded by internal.Auth()
// (X-Internal-Token), so these methods assume a trusted caller.
package internalapi

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/model/auth"
	"github.com/authboot/authboot-server/biz/model/common"
	"github.com/authboot/authboot-server/biz/model/internalapi"
	"github.com/authboot/authboot-server/biz/model/user"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/errno"
)

// internalSessionStore validates that a presented token's session is still
// live (not logged out / revoked).
var internalSessionStore redis.SessionStore

// InternalService serves the internal API.
type InternalService struct {
	ctx context.Context
	c   *app.RequestContext

	userDAO *db.UserDAO
}

// NewInternalService creates an internal API service.
func NewInternalService(ctx context.Context, c *app.RequestContext) *InternalService {
	return &InternalService{
		ctx:     ctx,
		c:       c,
		userDAO: db.NewUserDAO(db.DB),
	}
}

// IntrospectToken validates an access token and returns its auth context. It
// accepts both namespaces (user first, then admin — the two token kinds are
// signed with different keys, so a token can only parse as one). A token whose
// session has been revoked is reported as invalid.
func (s *InternalService) IntrospectToken(req *internalapi.IntrospectTokenRequest) (*internalapi.IntrospectTokenResponse, error) {
	if req.AccessToken == "" {
		return nil, errno.ParamErr
	}
	// App user token.
	if claims, err := jwt.ParseUserToken(req.AccessToken); err == nil {
		_, sessErr := internalSessionStore.Get(jwt.SubjectUser, claims.SessionID)
		resp := &internalapi.IntrospectTokenResponse{
			Code:    errno.SuccessCode,
			Message: errno.SuccessMsg,
			Valid:   claims.SessionID != "" && sessErr == nil,
			Subject: "user",
			UserContext: &auth.AuthContext{
				UserId:         claims.UserID,
				OrganizationId: claims.OrganizationID,
				SessionId:      claims.SessionID,
			},
		}
		if claims.ExpiresAt != nil {
			resp.ExpiresAt = claims.ExpiresAt.Time.Unix()
		}
		return resp, nil
	}
	// Platform admin token.
	if claims, err := jwt.ParseAdminToken(req.AccessToken); err == nil {
		_, sessErr := internalSessionStore.Get(jwt.SubjectAdmin, claims.SessionID)
		resp := &internalapi.IntrospectTokenResponse{
			Code:    errno.SuccessCode,
			Message: errno.SuccessMsg,
			Valid:   claims.SessionID != "" && sessErr == nil,
			Subject: "admin",
			AdminContext: &auth.AdminAuthContext{
				AccountId:      claims.AdminID,
				OrganizationId: claims.OrganizationID,
				SessionId:      claims.SessionID,
			},
		}
		if claims.ExpiresAt != nil {
			resp.ExpiresAt = claims.ExpiresAt.Time.Unix()
		}
		return resp, nil
	}
	return &internalapi.IntrospectTokenResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Valid:   false,
	}, nil
}

// GetUser returns an App user by id for trusted internal callers. Unlike the
// admin API this lookup is not organization-scoped: the internal token itself
// is the trust boundary.
func (s *InternalService) GetUser(req *internalapi.GetInternalUserRequest) (*internalapi.GetInternalUserResponse, error) {
	if req.UserId == 0 {
		return nil, errno.ParamErr
	}
	u, err := s.userDAO.QueryUserById(req.UserId)
	if err != nil {
		return nil, err
	}
	return &internalapi.GetInternalUserResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		User:    toInternalUser(u),
	}, nil
}

// toInternalUser maps a db user row to the API user view. A zero status (legacy
// rows) is reported as ENABLED.
func toInternalUser(u *db.User) *user.User {
	status := common.Status(u.Status)
	if status == common.Status_STATUS_UNKNOWN {
		status = common.Status_STATUS_ENABLED
	}
	return &user.User{
		Id:             u.ID,
		OrganizationId: u.OrganizationID,
		Nickname:       u.UserName,
		Avatar:         u.Avatar,
		Status:         status,
		CreatedAt:      u.CreatedAt,
		UpdatedAt:      u.UpdatedAt,
	}
}
