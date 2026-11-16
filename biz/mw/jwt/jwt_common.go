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

package jwt

import (
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol/consts"

	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/authboot/authboot-server/pkg/utils"
)

const (
	SubjectAdmin = "admin"
	SubjectUser  = "user"
)

// Admin (internal platform accounts) and User (external org customers) are two
// fully isolated identity systems: each has its OWN signing key + token logic
// (admin_token.go / user_token.go) and its OWN session guard + subject constant
// (session_admin.go / session_user.go). This file holds ONLY the pieces both
// genuinely share — Go forbids declaring e.g. bearerToken twice in one package.

// appAccessTTL is the default short lifetime shared by admin and user access
// tokens. Access tokens are not revoked individually; they expire quickly, and
// the session guards reject a token whose server-side session has been revoked.
// An organization can override the admin-side duration via its settings.
const appAccessTTL = time.Duration(constants.AppAccessTokenTTLSeconds) * time.Second

// DefaultAccessTTL 返回 admin/user access token 的全局默认有效时长。
// 组织可通过 tb_organization.settings 覆盖 admin 侧时长（见 db.AdminAccessTokenTTL）。
func DefaultAccessTTL() time.Duration { return appAccessTTL }

// sessionStore is the shared server-side session store. Sessions are still
// namespaced by subject (SubjectAdmin / SubjectUser), so admin and user never mix.
var sessionStore redis.SessionStore

// Context keys populated on a successful session check, for downstream
// handlers/services. For admin, CtxKeyUserID carries the platform account id;
// for user, it carries the org user id.
const (
	CtxKeyUserID    = "current_user_id"
	CtxKeyOrgID     = "organization_id"
	CtxKeySessionID = "session_id"
)

// bearerToken extracts the token from an "Authorization: Bearer <token>" header,
// tolerating a raw token without the "Bearer " prefix.
func bearerToken(c *app.RequestContext) string {
	h := strings.TrimSpace(string(c.GetHeader("Authorization")))
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return h
}

// rejectUnauthorized aborts the request chain with a 401 and the standard
// authorization-failed body.
func rejectUnauthorized(c *app.RequestContext) {
	c.JSON(consts.StatusUnauthorized, utils.BuildBaseResp(errno.AuthorizationFailedErr))
	c.Abort()
}
