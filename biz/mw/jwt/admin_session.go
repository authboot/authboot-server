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
	"context"

	"github.com/authboot/authboot-server/biz/dal/db"

	"github.com/cloudwego/hertz/pkg/app"
)

// AdminSessionAuth guards INTERNAL admin routes (/api/v1/admin/...). It accepts
// only admin tokens (verified with the admin key) whose admin-namespace session
// is still live. Because AdminLogout revokes the session, a logged-out but
// not-yet-expired token is rejected here.
//
// Fail-closed: a missing session OR a redis error both reject the request. User
// tokens, or tokens without a session id, are also rejected.
func AdminSessionAuth() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		token := bearerToken(c)
		if token == "" {
			rejectUnauthorized(c)
			return
		}
		claims, err := ParseAdminToken(token)
		if err != nil {
			rejectUnauthorized(c)
			return
		}
		if claims.SessionID == "" {
			rejectUnauthorized(c)
			return
		}
		rec, err := sessionStore.Get(SubjectAdmin, claims.SessionID)
		if err != nil || rec.AccountID != claims.AdminID ||
			db.CheckAdminMFAGeneration(claims.AdminID, rec.MFAGeneration) != nil ||
			db.ActiveSubject(SubjectAdmin, claims.AdminID, claims.OrganizationID) != nil {
			rejectUnauthorized(c)
			return
		}

		c.Set(CtxKeyUserID, claims.AdminID)
		c.Set(CtxKeyOrgID, claims.OrganizationID)
		c.Set(CtxKeySessionID, claims.SessionID)
		if !authorizeAdminResource(c, claims.AdminID, claims.OrganizationID) {
			c.AbortWithStatus(403)
			return
		}
		installAuthorizedBinding(c)
		if !consumeAdminStepUp(c) {
			c.AbortWithStatus(403)
			return
		}
		c.Next(ctx)
	}
}
