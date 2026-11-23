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
	"encoding/json"
	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/pkg/clientip"
	"github.com/cloudwego/hertz/pkg/common/hlog"

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
		rec, err := sessionStore.Get(SubjectUser, claims.SessionID)
		if err != nil || rec.AccountID != claims.UserID || rec.OrganizationID != claims.OrganizationID ||
			db.ActiveSubject(SubjectUser, claims.UserID, claims.OrganizationID) != nil {
			rejectUnauthorized(c)
			return
		}

		c.Set(CtxKeyUserID, claims.UserID)
		c.Set(CtxKeyOrgID, claims.OrganizationID)
		c.Set(CtxKeySessionID, claims.SessionID)
		if active, err := sessionStore.TouchUser(claims.OrganizationID, claims.UserID, claims.SessionID, clientip.FromContext(c)); err != nil {
			hlog.CtxWarnf(ctx, "user activity update failed: %v", err)
		} else if active != nil {
			location, _ := json.Marshal(active.LastActiveLocation)
			if err := db.DB.Model(&db.UserSessionRow{}).
				Where("organization_id = ? AND user_id = ? AND session_id = ? AND status = ? AND last_active_at <= ?", active.OrganizationID, active.AccountID, active.SessionID, db.SessionRowActive, active.LastActiveAt).
				Updates(map[string]interface{}{"last_active_at": active.LastActiveAt, "last_active_ip": active.LastActiveIP, "last_active_location": string(location)}).Error; err != nil {
				hlog.CtxWarnf(ctx, "persist session activity failed: %v", err)
			}
			if err := db.DB.Model(&db.UserDevice{}).
				Where("organization_id = ? AND user_id = ? AND device_id = ? AND last_active_at <= ?", active.OrganizationID, active.AccountID, active.DeviceID, active.LastActiveAt).
				Updates(map[string]interface{}{"last_active_at": active.LastActiveAt, "last_active_ip": active.LastActiveIP, "last_active_location": string(location)}).Error; err != nil {
				hlog.CtxWarnf(ctx, "persist device activity failed: %v", err)
			}
		}
		c.Next(ctx)
	}
}
