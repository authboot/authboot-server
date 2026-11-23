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
	"log"
	"sort"
	"strconv"
	"time"

	"github.com/go-redis/redis/v7"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/geoip"
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
	LoginMetadata
	LastActiveAt       int64          `json:"last_active_at"`
	LastActiveIP       string         `json:"last_active_ip"`
	LastActiveLocation geoip.Location `json:"last_active_location"`
	SessionID          string         `json:"session_id"`
	AccountID          int64          `json:"account_id"`
	OrganizationID     int64          `json:"organization_id"`
	DeviceID           string         `json:"device_id"`
	DeviceName         string         `json:"device_name"`
	RefreshToken       string         `json:"refresh_token"`
	CreatedAt          int64          `json:"created_at"`
	ExpiresAt          int64          `json:"expires_at"`
}

type LoginMetadata struct {
	SessionVersion int64          `json:"session_version,omitempty"`
	MFAGeneration  int64          `json:"mfa_generation,omitempty"`
	IP             string         `json:"ip,omitempty"`
	UserAgent      string         `json:"user_agent,omitempty"`
	ClientID       int64          `json:"client_id,omitempty"`
	Location       geoip.Location `json:"location"`
}

// SessionStore is the facade for the server-side session/refresh store. Every
// method takes a subject ("admin" / "user") that namespaces its keys.
type SessionStore struct{}

func (SessionStore) Healthy() error {
	if rdbSession == nil {
		return ErrSessionStoreUnavailable
	}
	return rdbSession.Ping().Err()
}

// ByRefresh authenticates without consuming. Rotate must still perform its CAS.
func (SessionStore) ByRefresh(subject, token string) (*SessionRecord, error) {
	if rdbSession == nil {
		return nil, ErrSessionStoreUnavailable
	}
	sid, err := rdbSession.Get(refreshKey(subject, token)).Result()
	if err == redis.Nil {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	rec, err := getSession(subject, sid)
	if err != nil {
		return nil, err
	}
	if rec.RefreshToken != token {
		return nil, ErrSessionNotFound
	}
	if err := checkSessionVersion(subject, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

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
func (SessionStore) Create(subject string, accountID, organizationID int64, deviceID, deviceName string, ttl time.Duration, metadata ...LoginMetadata) (*SessionRecord, error) {
	if ttl.Milliseconds() <= 0 {
		return nil, errors.New("redis: session TTL must be positive")
	}
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
		LastActiveAt:   now.Unix(),
		ExpiresAt:      now.Add(ttl).Unix(),
	}
	if len(metadata) > 0 {
		rec.LoginMetadata = metadata[0]
		rec.LastActiveIP, rec.LastActiveLocation = rec.IP, rec.Location
	}
	save := func() error { return saveSession(subject, rec, ttl) }
	if db.DB != nil {
		save = func() error {
			return db.DB.Transaction(func(tx *gorm.DB) error {
				if err := checkSessionVersionDB(tx.Clauses(clause.Locking{Strength: "UPDATE"}), subject, rec); err != nil {
					return err
				}
				return saveSession(subject, rec, ttl)
			})
		}
	}
	if err := save(); err != nil {
		return nil, err
	}
	// 双写落库（best-effort）：Redis 是热路径，MySQL 留审计/巡检记录。
	persistSessionCreate(subject, rec)
	return rec, nil
}

// persistSessionCreate 把新会话写入 tb_admin_sessions / tb_user_sessions。
// 写库失败只忽略：Redis 已写成功，落库是审计用途，不应阻塞登录。
func persistSessionCreate(subject string, rec *SessionRecord) {
	if db.DB == nil {
		return
	}
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
		LastActiveIP:       rec.LastActiveIP,
		LastActiveLocation: rec.LastActiveLocation,
		ClientID:           rec.ClientID,
		IP:                 rec.IP,
		UserAgent:          rec.UserAgent,
		Location:           rec.Location,
		SessionID:          rec.SessionID,
		OrganizationID:     rec.OrganizationID,
		UserID:             rec.AccountID,
		DeviceID:           rec.DeviceID,
		DeviceName:         rec.DeviceName,
		Status:             db.SessionRowActive,
		CreatedAt:          rec.CreatedAt,
		ExpiresAt:          rec.ExpiresAt,
		LastActiveAt:       rec.CreatedAt,
	}
	if err := db.UpsertUserSessionRow(row); err != nil {
		log.Printf("persist user session failed: %v", err)
	}
}

// saveSession writes the session record, the refresh->sid lookup, and the
// per-account sid index, all in the subject's namespace with the given ttl.
func saveSession(subject string, rec *SessionRecord, ttl time.Duration) error {
	buf, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	uk := userSessionsKey(subject, rec.AccountID)
	return rdbSession.Eval(`
local kind = redis.call('TYPE', KEYS[3]).ok
if kind ~= 'none' and kind ~= 'set' then return redis.error_reply('invalid session index type') end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[3])
redis.call('SADD', KEYS[3], ARGV[2])
if redis.call('PTTL', KEYS[3]) < tonumber(ARGV[3]) then
 redis.call('PEXPIRE', KEYS[3], ARGV[3])
end
return 1`, []string{sessionKey(subject, rec.SessionID), refreshKey(subject, rec.RefreshToken), uk}, string(buf), rec.SessionID, ttl.Milliseconds()).Err()
}

// Rotate validates a presented refresh token and rotates it: the old token is
// invalidated and a new one issued for the SAME session (stable sid). Returns
// the updated record (new rec.RefreshToken). A token that is unknown/expired —
// including a replayed, already-rotated one — yields ErrSessionNotFound.
func (SessionStore) Rotate(subject, oldRefresh string, ttl time.Duration) (*SessionRecord, error) {
	if ttl.Milliseconds() <= 0 {
		return nil, errors.New("redis: session TTL must be positive")
	}
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
	if err := checkSessionVersion(subject, rec); err != nil {
		return nil, err
	}
	now := time.Now()
	rec.RefreshToken = newTok
	rec.ExpiresAt = now.Add(ttl).Unix()
	buf, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	// Compare and swap in Redis. A losing replay never revokes the winner;
	// a concurrent revoke leaves no record that this script could resurrect.
	updated, err := rdbSession.Eval(`
local raw = redis.call('GET', KEYS[1])
if not raw or redis.call('GET', KEYS[2]) ~= ARGV[1] then return '' end
local rec = cjson.decode(raw)
if rec.refresh_token ~= ARGV[2] then return '' end
if redis.call('EXISTS', KEYS[3]) ~= 0 then return '' end
local kind = redis.call('TYPE', KEYS[4]).ok
if kind ~= 'none' and kind ~= 'set' then return redis.error_reply('invalid session index type') end
local replacement = cjson.decode(ARGV[3])
rec.refresh_token = replacement.refresh_token
rec.expires_at = replacement.expires_at
redis.call('SET', KEYS[1], cjson.encode(rec), 'PX', ARGV[4])
redis.call('SET', KEYS[3], ARGV[1], 'PX', ARGV[4])
redis.call('DEL', KEYS[2])
redis.call('SADD', KEYS[4], ARGV[1])
if redis.call('PTTL', KEYS[4]) < tonumber(ARGV[4]) then
 redis.call('PEXPIRE', KEYS[4], ARGV[4])
end
return cjson.encode(rec)`, []string{sessionKey(subject, sid), refreshKey(subject, oldRefresh), refreshKey(subject, newTok), userSessionsKey(subject, rec.AccountID)}, sid, oldRefresh, string(buf), ttl.Milliseconds()).Text()
	if err != nil {
		return nil, err
	}
	if updated == "" {
		return nil, ErrSessionNotFound
	}
	if err := json.Unmarshal([]byte(updated), rec); err != nil {
		return nil, err
	}
	// A refresh must never upsert/revive an audit row concurrently revoked.
	if db.DB != nil && subject == constants.UserSubject {
		if err := db.DB.Model(&db.UserSessionRow{}).
			Where("session_id = ? AND organization_id = ? AND user_id = ? AND status = ?", rec.SessionID, rec.OrganizationID, rec.AccountID, db.SessionRowActive).
			Update("expires_at", rec.ExpiresAt).Error; err != nil {
			log.Printf("persist user refresh failed: %v", err)
		}
	} else {
		persistSessionCreate(subject, rec)
	}
	return rec, nil
}

// Get returns a session by sid within the subject's namespace, or
// ErrSessionNotFound. Useful for a "my devices" listing or validating a session
// referenced by an access token's sid.
func (SessionStore) Get(subject, sid string) (*SessionRecord, error) {
	if rdbSession == nil {
		return nil, ErrSessionStoreUnavailable
	}
	rec, err := getSession(subject, sid)
	if err != nil {
		return nil, err
	}
	if err := checkSessionVersion(subject, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

func checkSessionVersion(subject string, rec *SessionRecord) error {
	return checkSessionVersionDB(db.DB, subject, rec)
}

func checkSessionVersionDB(conn *gorm.DB, subject string, rec *SessionRecord) error {
	if conn == nil {
		return nil
	} // Isolated Redis tests have no SQL dependency.
	if subject == constants.UserSubject {
		var u db.User
		if err := conn.Where("id = ? AND organization_id = ?", rec.AccountID, rec.OrganizationID).First(&u).Error; err != nil {
			return err
		}
		if u.SessionVersion == rec.SessionVersion {
			return nil
		}
	}
	if subject == constants.AdminSubject {
		var u db.AdminUser
		if err := conn.First(&u, rec.AccountID).Error; err != nil {
			return err
		}
		if u.MFAGeneration == rec.MFAGeneration {
			return nil
		}
	}
	return ErrSessionNotFound
}

// GetWithDB uses the caller's transaction, avoiding a second connection and
// ensuring that authority checks see that transaction's security mutations.
func (SessionStore) GetWithDB(conn *gorm.DB, subject, sid string) (*SessionRecord, error) {
	if rdbSession == nil {
		return nil, ErrSessionStoreUnavailable
	}
	rec, err := getSession(subject, sid)
	if err != nil {
		return nil, err
	}
	if err := checkSessionVersionDB(conn, subject, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// RevokeBeforeVersion uses raw records so invalidated sessions can be cleaned.
// Session versions are immutable across refresh; Redis deletion is atomic.
func (SessionStore) RevokeBeforeVersion(subject string, account, org, version int64) error {
	if rdbSession == nil {
		return ErrSessionStoreUnavailable
	}
	if subject != constants.UserSubject && subject != constants.AdminSubject {
		return ErrSessionNotFound
	}
	ids, err := rdbSession.SMembers(userSessionsKey(subject, account)).Result()
	if err != nil {
		return err
	}
	for _, sid := range ids {
		rec, err := getSession(subject, sid)
		if err == ErrSessionNotFound {
			continue
		}
		if err != nil {
			return err
		}
		v := rec.SessionVersion
		if subject == constants.AdminSubject {
			v = rec.MFAGeneration
		}
		if rec.AccountID == account && (subject == constants.AdminSubject || rec.OrganizationID == org) && v < version {
			if db.DB != nil {
				var result *gorm.DB
				if subject == constants.AdminSubject {
					result = db.DB.Model(&db.AdminSessionRow{}).Where("session_id = ? AND account_id = ?", rec.SessionID, account).Update("status", db.SessionRowRevoked)
				} else {
					result = db.DB.Model(&db.UserSessionRow{}).Where("session_id = ? AND user_id = ? AND organization_id = ?", rec.SessionID, account, org).Update("status", db.SessionRowRevoked)
				}
				if result.Error != nil {
					return result.Error
				}
			}
			if err := deleteSession(subject, rec); err != nil {
				return err
			}
		}
	}
	return nil
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
	if db.DB != nil {
		_ = db.RevokeSessionRow(sid)
	}
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
	rec, err := getSession(subject, sid)
	if err == ErrSessionNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	return rdbSession.Eval(`
local raw = redis.call('GET', KEYS[1])
if not raw or redis.call('GET', KEYS[2]) ~= ARGV[1] then return 0 end
local rec = cjson.decode(raw)
if rec.refresh_token ~= ARGV[2] then return 0 end
redis.call('DEL', KEYS[1], KEYS[2])
redis.call('SREM', KEYS[3], ARGV[1])
return 1`, []string{sessionKey(subject, sid), refreshKey(subject, refreshToken), userSessionsKey(subject, rec.AccountID)}, sid, refreshToken).Err()
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
	if db.DB != nil {
		_ = db.RevokeAllSessionRowsFor(subject, accountID)
	}
	return nil // Preserve sessions added concurrently after the initial snapshot.
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
	return rdbSession.Eval(`
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local rec = cjson.decode(raw)
redis.call('DEL', ARGV[1] .. rec.refresh_token)
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[2])
return 1`, []string{sessionKey(subject, rec.SessionID), userSessionsKey(subject, rec.AccountID)}, refreshKey(subject, ""), rec.SessionID).Err()
}
