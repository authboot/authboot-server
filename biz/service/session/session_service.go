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

// Package session exposes server-side session management: listing an account's
// live sessions (devices) and revoking one or all of them. User sessions and
// admin sessions are isolated by namespace (jwt.SubjectUser / SubjectAdmin).
package session

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/model/session"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/errno"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

// sessionStore is the redis-backed session store (zero value is usable).
var sessionStore redis.SessionStore

// SessionService serves both the user self-service session routes (acting user
// from the token) and the admin session-management routes (org-scoped).
type SessionService struct {
	ctx context.Context
	c   *app.RequestContext

	userDAO       *db.UserDAO
	membershipDAO *db.OrganizationMembershipDAO
}

// NewSessionService creates a session management service.
func NewSessionService(ctx context.Context, c *app.RequestContext) *SessionService {
	return &SessionService{
		ctx:           ctx,
		c:             c,
		userDAO:       db.NewUserDAO(db.DB),
		membershipDAO: db.NewOrganizationMembershipDAO(db.DB),
	}
}

// ---------------------------------------------------------------------------
// App user sessions
// ---------------------------------------------------------------------------

// ListSessions lists a target user's live sessions. Admin-side: the user must
// belong to the given organization.
func (s *SessionService) ListSessions(req *session.ListSessionsRequest) (*session.ListSessionsResponse, error) {
	if req.OrganizationId == 0 || req.UserId == 0 {
		return nil, errno.ParamErr
	}
	if _, err := s.userDAO.QueryUserByIdInOrg(req.OrganizationId, req.UserId); err != nil {
		return nil, err
	}
	recs, err := sessionStore.ListForUser(jwt.SubjectUser, req.UserId)
	if err != nil {
		return nil, err
	}
	page, pageSize := normalizePaging(req.Page, req.PageSize)
	items, total := paginateSessions(recs, page, pageSize)
	return &session.ListSessionsResponse{
		Code:     errno.SuccessCode,
		Message:  errno.SuccessMsg,
		Sessions: items,
		Total:    total,
	}, nil
}

// RevokeAllSessions ends every session of a target user. Admin-side: the user
// must belong to the given organization.
func (s *SessionService) RevokeAllSessions(req *session.RevokeAllSessionsRequest) (*session.RevokeAllSessionsResponse, error) {
	if req.OrganizationId == 0 || req.UserId == 0 {
		return nil, errno.ParamErr
	}
	if _, err := s.userDAO.QueryUserByIdInOrg(req.OrganizationId, req.UserId); err != nil {
		return nil, err
	}
	if err := sessionStore.RevokeAllForUser(jwt.SubjectUser, req.UserId); err != nil {
		return nil, err
	}
	return &session.RevokeAllSessionsResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}, nil
}

// GetSession returns one of the CURRENT user's sessions. Sessions belonging to
// another account are reported as unauthorized, never leaked.
func (s *SessionService) GetSession(req *session.GetSessionRequest) (*session.GetSessionResponse, error) {
	me, err := s.currentUserID()
	if err != nil {
		return nil, err
	}
	rec, err := sessionStore.Get(jwt.SubjectUser, req.SessionId)
	if err != nil || rec.AccountID != me || rec.OrganizationID != s.c.GetInt64(jwt.CtxKeyOrgID) {
		return nil, errno.AuthorizationFailedErr
	}
	return &session.GetSessionResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Session: toSessionProto(rec),
	}, nil
}

// RevokeSession ends one of the CURRENT user's sessions (sign out this device).
func (s *SessionService) RevokeSession(req *session.RevokeSessionRequest) (*session.RevokeSessionResponse, error) {
	me, err := s.currentUserID()
	if err != nil {
		return nil, err
	}
	rec, err := sessionStore.Get(jwt.SubjectUser, req.SessionId)
	if err != nil || rec.AccountID != me || rec.OrganizationID != s.c.GetInt64(jwt.CtxKeyOrgID) {
		return nil, errno.AuthorizationFailedErr
	}
	if err := sessionStore.Revoke(jwt.SubjectUser, req.SessionId); err != nil {
		return nil, err
	}
	return &session.RevokeSessionResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}, nil
}

// ---------------------------------------------------------------------------
// Platform admin sessions
// ---------------------------------------------------------------------------

// ListAdminSessions lists a target admin account's live sessions. The caller
// may manage themselves, or an account that is a member of the current org.
func (s *SessionService) ListAdminSessions(req *session.ListAdminSessionsRequest) (*session.ListAdminSessionsResponse, error) {
	if req.AccountId == 0 {
		return nil, errno.ParamErr
	}
	adminID, orgID, err := s.currentAdmin()
	if err != nil {
		return nil, err
	}
	if !s.canManageAdmin(orgID, adminID, req.AccountId) {
		return nil, errno.PermissionDeniedErr
	}
	recs, err := sessionStore.ListForUser(jwt.SubjectAdmin, req.AccountId)
	if err != nil {
		return nil, err
	}
	page, pageSize := normalizePaging(req.Page, req.PageSize)
	items, total := paginateAdminSessions(recs, page, pageSize)
	if sid, ok := s.c.Get(jwt.CtxKeySessionID); ok {
		if current, _ := sid.(string); current != "" {
			for _, it := range items {
				it.Current = it.SessionId == current
			}
		}
	}
	return &session.ListAdminSessionsResponse{
		Code:     errno.SuccessCode,
		Message:  errno.SuccessMsg,
		Sessions: items,
		Total:    total,
	}, nil
}

// RevokeAllAdminSessions ends every session of a target admin account.
func (s *SessionService) RevokeAllAdminSessions(req *session.RevokeAllAdminSessionsRequest) (*session.RevokeAllAdminSessionsResponse, error) {
	if req.AccountId == 0 {
		return nil, errno.ParamErr
	}
	adminID, orgID, err := s.currentAdmin()
	if err != nil {
		return nil, err
	}
	if !s.canManageAdmin(orgID, adminID, req.AccountId) {
		return nil, errno.PermissionDeniedErr
	}
	if err := sessionStore.RevokeAllForUser(jwt.SubjectAdmin, req.AccountId); err != nil {
		return nil, err
	}
	return &session.RevokeAllAdminSessionsResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}, nil
}

// GetAdminSession returns an admin session. The caller may read their own
// sessions, or sessions currently bound to their org.
func (s *SessionService) GetAdminSession(req *session.GetAdminSessionRequest) (*session.GetAdminSessionResponse, error) {
	adminID, orgID, err := s.currentAdmin()
	if err != nil {
		return nil, err
	}
	rec, err := sessionStore.Get(jwt.SubjectAdmin, req.SessionId)
	if err != nil {
		return nil, errno.AuthorizationFailedErr
	}
	if rec.AccountID != adminID && rec.OrganizationID != orgID {
		return nil, errno.PermissionDeniedErr
	}
	return &session.GetAdminSessionResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Session: toAdminSessionProto(rec),
	}, nil
}

// RevokeAdminSession ends an admin session (force sign-out on that device).
func (s *SessionService) RevokeAdminSession(req *session.RevokeAdminSessionRequest) (*session.RevokeAdminSessionResponse, error) {
	adminID, orgID, err := s.currentAdmin()
	if err != nil {
		return nil, err
	}
	rec, err := sessionStore.Get(jwt.SubjectAdmin, req.SessionId)
	if err != nil {
		return nil, errno.AuthorizationFailedErr
	}
	if rec.AccountID != adminID && rec.OrganizationID != orgID {
		return nil, errno.PermissionDeniedErr
	}
	if err := sessionStore.Revoke(jwt.SubjectAdmin, req.SessionId); err != nil {
		return nil, err
	}
	return &session.RevokeAdminSessionResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}, nil
}

// canManageAdmin reports whether the current admin may manage targetAccountID:
// themselves, or a member of the org the token is currently bound to.
func (s *SessionService) canManageAdmin(orgID, currentAdminID, targetAccountID int64) bool {
	if targetAccountID == currentAdminID {
		return true
	}
	if _, err := s.membershipDAO.QueryMembership(orgID, targetAccountID); err != nil {
		return false
	}
	return true
}

// currentUserID reads the authenticated App user id (UserSessionAuth).
func (s *SessionService) currentUserID() (int64, error) {
	v, ok := s.c.Get(jwt.CtxKeyUserID)
	if !ok {
		return 0, errno.AuthorizationFailedErr
	}
	id, ok := v.(int64)
	if !ok || id == 0 {
		return 0, errno.AuthorizationFailedErr
	}
	return id, nil
}

// currentAdmin reads the authenticated admin id and bound org (AdminSessionAuth).
func (s *SessionService) currentAdmin() (adminID, orgID int64, err error) {
	v, ok := s.c.Get(jwt.CtxKeyUserID)
	if !ok {
		return 0, 0, errno.AuthorizationFailedErr
	}
	adminID, ok = v.(int64)
	if !ok || adminID == 0 {
		return 0, 0, errno.AuthorizationFailedErr
	}
	org, ok := s.c.Get(jwt.CtxKeyOrgID)
	if !ok {
		return 0, 0, errno.AuthorizationFailedErr
	}
	orgID, _ = org.(int64)
	return adminID, orgID, nil
}

// normalizePaging clamps page/page_size into sane bounds.
func normalizePaging(page, pageSize int32) (int, int) {
	p := int(page)
	if p < 1 {
		p = 1
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

// paginateSessions slices and maps user sessions for one page.
func paginateSessions(recs []*redis.SessionRecord, page, pageSize int) ([]*session.Session, int64) {
	total := int64(len(recs))
	start, end := pageBounds(total, page, pageSize)
	items := make([]*session.Session, 0, end-start)
	for _, rec := range recs[start:end] {
		items = append(items, toSessionProto(rec))
	}
	return items, total
}

// paginateAdminSessions slices and maps admin sessions for one page.
func paginateAdminSessions(recs []*redis.SessionRecord, page, pageSize int) ([]*session.AdminSession, int64) {
	total := int64(len(recs))
	start, end := pageBounds(total, page, pageSize)
	items := make([]*session.AdminSession, 0, end-start)
	for _, rec := range recs[start:end] {
		items = append(items, toAdminSessionProto(rec))
	}
	return items, total
}

// pageBounds returns the [start, end) slice bounds for a page.
func pageBounds(total int64, page, pageSize int) (int, int) {
	start := (page - 1) * pageSize
	if int64(start) > total {
		start = int(total)
	}
	end := start + pageSize
	if int64(end) > total {
		end = int(total)
	}
	return start, end
}

// toSessionProto maps a stored session record to the App-user session view.
func toSessionProto(rec *redis.SessionRecord) *session.Session {
	return &session.Session{
		LastActiveAt:       rec.LastActiveAt,
		LastActiveIp:       rec.LastActiveIP,
		LastActiveLocation: LocationProto(rec.LastActiveLocation),
		UserAgent:          rec.UserAgent,
		ClientId:           rec.ClientID,
		Ip:                 rec.IP,
		Location:           LocationProto(rec.Location),
		SessionId:          rec.SessionID,
		OrganizationId:     rec.OrganizationID,
		UserId:             rec.AccountID,
		DeviceId:           rec.DeviceID,
		DeviceName:         rec.DeviceName,
		Status:             session.SessionStatus_SESSION_STATUS_ACTIVE,
		CreatedAt:          rec.CreatedAt,
		ExpiresAt:          rec.ExpiresAt,
	}
}

// toAdminSessionProto maps a stored session record to the admin session view.
func toAdminSessionProto(rec *redis.SessionRecord) *session.AdminSession {
	return &session.AdminSession{
		SessionId:             rec.SessionID,
		AccountId:             rec.AccountID,
		CurrentOrganizationId: rec.OrganizationID,
		DeviceId:              rec.DeviceID,
		DeviceName:            rec.DeviceName,
		Status:                session.SessionStatus_SESSION_STATUS_ACTIVE,
		CreatedAt:             rec.CreatedAt,
		ExpiresAt:             rec.ExpiresAt,
	}
}
