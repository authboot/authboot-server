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

	"github.com/cloudwego/hertz/pkg/app"
)

// UserSessionAuth guards EXTERNAL org user (customer) routes. It accepts only
// user tokens (verified with the user key) whose user-namespace session is
// still live. Because Logout revokes the session, a logged-out but not-yet-
// expired token is rejected here.
//
// Fail-closed: a missing session OR a redis error both reject the request. Admin
// tokens, or tokens without a session id, are also rejected.
func UserSessionAuth() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		token := bearerToken(c)
		if token == "" {
			rejectUnauthorized(c)
			return
		}
		claims, err := ParseUserToken(token)
		if err != nil {
			rejectUnauthorized(c)
			return
		}
		if claims.SessionID == "" {
			rejectUnauthorized(c)
			return
		}
		if _, err := sessionStore.Get(SubjectUser, claims.SessionID); err != nil {
			rejectUnauthorized(c)
			return
		}

		c.Set(CtxKeyUserID, claims.UserID)
		c.Set(CtxKeyOrgID, claims.OrganizationID)
		c.Set(CtxKeySessionID, claims.SessionID)
		c.Next(ctx)
	}
}
