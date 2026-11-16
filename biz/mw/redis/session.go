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

package redis

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/go-redis/redis/v7"
	"github.com/google/uuid"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/pkg/constants"
)

// Server-side session / refresh-token store. Access tokens stay stateless and
// short-lived (minutes); the refresh token is an opaque random string whose
// authority lives entirely here, so logout = delete the record and refresh =
// rotate it. Every key is namespaced by subject ("admin" / "user") so the two
// identity systems can never collide or be looked up across the boundary:
//
//	session:<subject>:<sid>            -> JSON SessionRecord (source of truth)
//	refresh:<subject>:<token>          -> sid (lookup from a presented refresh token)
//	user_sessions:<subject>:<account>  -> SET of sids (to revoke all of an account's sessions)
const (
	sessionKeyPrefix   = "session:"
	refreshKeyPrefix   = "refresh:"
	userSessionsPrefix = "user_sessions:"
)

// DefaultSessionTTL is the lifetime of a session / refresh token. Access tokens
// are short-lived (jwt.appAccessTTL) and refreshed within this window.
const DefaultSessionTTL = 30 * 24 * time.Hour

// ErrSessionStoreUnavailable is returned when redis is not initialized. Unlike
// the best-effort code cache, the session store fails closed: without it the
// refresh/logout guarantees cannot hold.
var ErrSessionStoreUnavailable = errors.New("redis: session store is not initialized")

// ErrSessionNotFound means the session/refresh token is unknown, expired, or
// already revoked (also covers a replayed, already-rotated refresh token).
var ErrSessionNotFound = errors.New("redis: session not found")

// SessionRecord is one login session (one device). RefreshToken holds the
// CURRENT opaque token after any rotations.
type SessionRecord struct {
	SessionID      string `json:"session_id"`
	AccountID      int64  `json:"account_id"`
	OrganizationID int64  `json:"organization_id"`
	DeviceID       string `json:"device_id"`
	DeviceName     string `json:"device_name"`
	RefreshToken   string `json:"refresh_token"`
	CreatedAt      int64  `json:"created_at"`
	ExpiresAt      int64  `json:"expires_at"`
}

// SessionStore is the facade for the server-side session/refresh store. Every
// method takes a subject ("admin" / "user") that namespaces its keys.
type SessionStore struct{}

func sessionKey(subject, sid string) string { return sessionKeyPrefix + subject + ":" + sid }
func refreshKey(subject, tok string) string { return refreshKeyPrefix + subject + ":" + tok }
func userSessionsKey(subject string, accountID int64) string {
	return userSessionsPrefix + subject + ":" + strconv.FormatInt(accountID, 10)
}

// newRefreshToken returns a 256-bit opaque, URL-safe random token.
func newRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create opens a new session (in the subject's namespace) for an account/device
// and returns the record, including the freshly minted opaque refresh token
// (rec.RefreshToken) and session id (rec.SessionID). ttl is the refresh/session
// lifetime. The caller mints the short-lived access token separately
// (jwt.Generate{Admin,User}AccessToken), passing rec.SessionID.
func (SessionStore) Create(subject string, accountID, organizationID int64, deviceID, deviceName string, ttl time.Duration) (*SessionRecord, error) {
	if rdbSession == nil {
		return nil, ErrSessionStoreUnavailable
	}
	token, err := newRefreshToken()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	rec := &SessionRecord{
		SessionID:      uuid.NewString(),
		AccountID:      accountID,
		OrganizationID: organizationID,
		DeviceID:       deviceID,
		DeviceName:     deviceName,
		RefreshToken:   token,
		CreatedAt:      now.Unix(),
		ExpiresAt:      now.Add(ttl).Unix(),
	}
	if err := saveSession(subject, rec, ttl); err != nil {
		return nil, err
	}
	// 双写落库（best-effort）：Redis 是热路径，MySQL 留审计/巡检记录。
	persistSessionCreate(subject, rec)
	return rec, nil
}

// persistSessionCreate 把新会话写入 tb_admin_sessions / tb_user_sessions。
// 写库失败只忽略：Redis 已写成功，落库是审计用途，不应阻塞登录。
func persistSessionCreate(subject string, rec *SessionRecord) {
	defer func() {
		// db 包未初始化（如单测环境）时静默跳过
		_ = recover()
	}()
	if subject == constants.AdminSubject {
		row := &db.AdminSessionRow{
			SessionID:      rec.SessionID,
			AccountID:      rec.AccountID,
			OrganizationID: rec.OrganizationID,
			DeviceID:       rec.DeviceID,
			DeviceName:     rec.DeviceName,
			Status:         db.SessionRowActive,
			CreatedAt:      rec.CreatedAt,
			ExpiresAt:      rec.ExpiresAt,
			LastActiveAt:   rec.CreatedAt,
		}
		_ = db.UpsertAdminSessionRow(row)
		return
	}
	row := &db.UserSessionRow{
		SessionID:      rec.SessionID,
		OrganizationID: rec.OrganizationID,
		UserID:         rec.AccountID,
		DeviceID:       rec.DeviceID,
		DeviceName:     rec.DeviceName,
		Status:         db.SessionRowActive,
		CreatedAt:      rec.CreatedAt,
		ExpiresAt:      rec.ExpiresAt,
		LastActiveAt:   rec.CreatedAt,
	}
	_ = db.UpsertUserSessionRow(row)
}

// saveSession writes the session record, the refresh->sid lookup, and the
// per-account sid index, all in the subject's namespace with the given ttl.
func saveSession(subject string, rec *SessionRecord, ttl time.Duration) error {
	buf, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := rdbSession.Set(sessionKey(subject, rec.SessionID), buf, ttl).Err(); err != nil {
		return err
	}
	if err := rdbSession.Set(refreshKey(subject, rec.RefreshToken), rec.SessionID, ttl).Err(); err != nil {
		return err
	}
	uk := userSessionsKey(subject, rec.AccountID)
	if err := rdbSession.SAdd(uk, rec.SessionID).Err(); err != nil {
		return err
	}
	// Keep the index alive at least as long as the longest-lived session.
	return rdbSession.Expire(uk, ttl).Err()
}

// Rotate validates a presented refresh token and rotates it: the old token is
// invalidated and a new one issued for the SAME session (stable sid). Returns
// the updated record (new rec.RefreshToken). A token that is unknown/expired —
// including a replayed, already-rotated one — yields ErrSessionNotFound.
func (SessionStore) Rotate(subject, oldRefresh string, ttl time.Duration) (*SessionRecord, error) {
	if rdbSession == nil {
		return nil, ErrSessionStoreUnavailable
	}
	sid, err := rdbSession.Get(refreshKey(subject, oldRefresh)).Result()
	if err == redis.Nil {
		return nil, ErrSessionNotFound
	} else if err != nil {
		return nil, err
	}
	rec, err := getSession(subject, sid)
	if err != nil {
		return nil, err
	}

	newTok, err := newRefreshToken()
	if err != nil {
		return nil, err
	}
	// Invalidate the old token first so it cannot be reused.
	if err := rdbSession.Del(refreshKey(subject, oldRefresh)).Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	rec.RefreshToken = newTok
	rec.ExpiresAt = now.Add(ttl).Unix()
	if err := saveSession(subject, rec, ttl); err != nil {
		return nil, err
	}
	// rotate 后 sid 不变，落库 upsert 刷新过期时间与最后活跃时间
	persistSessionCreate(subject, rec)
	return rec, nil
}

// Get returns a session by sid within the subject's namespace, or
// ErrSessionNotFound. Useful for a "my devices" listing or validating a session
// referenced by an access token's sid.
func (SessionStore) Get(subject, sid string) (*SessionRecord, error) {
	if rdbSession == nil {
		return nil, ErrSessionStoreUnavailable
	}
	return getSession(subject, sid)
}

func getSession(subject, sid string) (*SessionRecord, error) {
	buf, err := rdbSession.Get(sessionKey(subject, sid)).Result()
	if err == redis.Nil {
		return nil, ErrSessionNotFound
	} else if err != nil {
		return nil, err
	}
	var rec SessionRecord
	if err := json.Unmarshal([]byte(buf), &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// Revoke ends a single session (one device logout) in the subject's namespace,
// removing the session record, its current refresh token, and the per-account
// index entry. Revoking a missing session is a no-op.
func (SessionStore) Revoke(subject, sid string) error {
	if rdbSession == nil {
		return ErrSessionStoreUnavailable
	}
	rec, err := getSession(subject, sid)
	if err == ErrSessionNotFound {
		return nil
	} else if err != nil {
		return err
	}
	// 落库行标记 revoked（best-effort，审计用途）
	_ = db.RevokeSessionRow(sid)
	return deleteSession(subject, rec)
}

// RevokeByRefresh ends the session identified by a presented refresh token.
func (SessionStore) RevokeByRefresh(subject, refreshToken string) error {
	if rdbSession == nil {
		return ErrSessionStoreUnavailable
	}
	sid, err := rdbSession.Get(refreshKey(subject, refreshToken)).Result()
	if err == redis.Nil {
		return nil
	} else if err != nil {
		return err
	}
	return SessionStore{}.Revoke(subject, sid)
}

// RevokeAllForUser ends every session of an account in the subject's namespace
// ("logout everywhere").
func (SessionStore) RevokeAllForUser(subject string, accountID int64) error {
	if rdbSession == nil {
		return ErrSessionStoreUnavailable
	}
	uk := userSessionsKey(subject, accountID)
	sids, err := rdbSession.SMembers(uk).Result()
	if err != nil {
		return err
	}
	for _, sid := range sids {
		rec, err := getSession(subject, sid)
		if err == ErrSessionNotFound {
			continue
		} else if err != nil {
			return err
		}
		if err := deleteSession(subject, rec); err != nil {
			return err
		}
	}
	// 落库行批量标记 revoked（best-effort，审计用途）
	_ = db.RevokeAllSessionRowsFor(subject, accountID)
	return rdbSession.Del(uk).Err()
}

// ListForUser returns every live session of an account in the subject's
// namespace, newest first. Sessions that expired between the index read and
// the record read are skipped.
func (SessionStore) ListForUser(subject string, accountID int64) ([]*SessionRecord, error) {
	if rdbSession == nil {
		return nil, ErrSessionStoreUnavailable
	}
	sids, err := rdbSession.SMembers(userSessionsKey(subject, accountID)).Result()
	if err != nil {
		return nil, err
	}
	recs := make([]*SessionRecord, 0, len(sids))
	for _, sid := range sids {
		rec, err := getSession(subject, sid)
		if err == ErrSessionNotFound {
			continue
		} else if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].CreatedAt > recs[j].CreatedAt })
	return recs, nil
}

// deleteSession removes a record's session key, refresh lookup, and index entry
// within the subject's namespace.
func deleteSession(subject string, rec *SessionRecord) error {
	if err := rdbSession.Del(sessionKey(subject, rec.SessionID)).Err(); err != nil {
		return err
	}
	if err := rdbSession.Del(refreshKey(subject, rec.RefreshToken)).Err(); err != nil {
		return err
	}
	return rdbSession.SRem(userSessionsKey(subject, rec.AccountID), rec.SessionID).Err()
}
