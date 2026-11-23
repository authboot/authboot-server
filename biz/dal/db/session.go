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

package db

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/geoip"
)

// Session persistence: Redis (biz/mw/redis/session.go) remains the hot path for
// token refresh / revocation; these MySQL tables are the audit / inspection
// record — "which account logged in from where and when, and is the session
// still alive". Admin and user sessions live in SEPARATE tables so the two
// identity systems never mix (mirrors the Redis subject namespacing).

// AdminSessionRow is one platform-admin login session (one device).
type AdminSessionRow struct {
	ID             int64  `json:"id" gorm:"primaryKey;autoIncrement"`
	SessionID      string `json:"session_id" gorm:"column:session_id;type:varchar(64);not null;uniqueIndex"`
	AccountID      int64  `json:"account_id" gorm:"column:account_id;not null;index;index:idx_admin_session_account,priority:1"`
	OrganizationID int64  `json:"organization_id" gorm:"column:organization_id;not null;default:0"` // 0 = 未绑定组织（平台级令牌）
	DeviceID       string `json:"device_id" gorm:"column:device_id;type:varchar(64)"`
	DeviceName     string `json:"device_name" gorm:"column:device_name;type:varchar(128)"`
	IP             string `json:"ip" gorm:"column:ip;type:varchar(64)"`
	UserAgent      string `json:"user_agent" gorm:"column:user_agent;type:varchar(255)"`
	Status         int8   `json:"status" gorm:"column:status;type:tinyint;not null;default:1;index"` // 1 active / 2 revoked
	CreatedAt      int64  `json:"created_at" gorm:"column:created_at;not null"`
	ExpiresAt      int64  `json:"expires_at" gorm:"column:expires_at;not null;index;index:idx_admin_session_account,priority:2"`
	LastActiveAt   int64  `json:"last_active_at" gorm:"column:last_active_at;not null"`
}

// TableName defines the table name for the AdminSessionRow struct.
func (AdminSessionRow) TableName() string { return constants.AdminSessionTableName }

// UserSessionRow is one App-user login session (one device), symmetric to
// AdminSessionRow but org-bound (an App user always belongs to one org).
type UserSessionRow struct {
	LastActiveIP       string         `json:"last_active_ip" gorm:"type:varchar(64)"`
	LastActiveLocation geoip.Location `json:"last_active_location" gorm:"serializer:json;type:text"`
	Location           geoip.Location `json:"location" gorm:"serializer:json;type:text"`
	ID                 int64          `json:"id" gorm:"primaryKey;autoIncrement"`
	SessionID          string         `json:"session_id" gorm:"column:session_id;type:varchar(64);not null;uniqueIndex"`
	OrganizationID     int64          `json:"organization_id" gorm:"column:organization_id;not null;index"`
	UserID             int64          `json:"user_id" gorm:"column:user_id;not null;index;index:idx_user_session_user,priority:1"`
	ClientID           int64          `json:"client_id" gorm:"column:client_id"`
	DeviceID           string         `json:"device_id" gorm:"column:device_id;type:varchar(64)"`
	DeviceName         string         `json:"device_name" gorm:"column:device_name;type:varchar(128)"`
	IP                 string         `json:"ip" gorm:"column:ip;type:varchar(64)"`
	UserAgent          string         `json:"user_agent" gorm:"column:user_agent;type:varchar(255)"`
	Status             int8           `json:"status" gorm:"column:status;type:tinyint;not null;default:1;index"` // 1 active / 2 revoked
	CreatedAt          int64          `json:"created_at" gorm:"column:created_at;not null"`
	ExpiresAt          int64          `json:"expires_at" gorm:"column:expires_at;not null;index;index:idx_user_session_user,priority:2"`
	LastActiveAt       int64          `json:"last_active_at" gorm:"column:last_active_at;not null"`
}

// TableName defines the table name for the UserSessionRow struct.
func (UserSessionRow) TableName() string { return constants.UserSessionTableName }

// session status values shared by both session tables
const (
	SessionRowActive  = 1
	SessionRowRevoked = 2
)

// UpsertAdminSessionRow inserts or refreshes a persisted admin session row
// (login re-uses sid after rotate, so upsert on session_id).
func UpsertAdminSessionRow(row *AdminSessionRow) error {
	if row == nil {
		return nil
	}
	return DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "session_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"organization_id", "device_id", "device_name", "ip", "user_agent",
			"status", "expires_at", "last_active_at",
		}),
	}).Create(row).Error
}

// UpsertUserSessionRow inserts or refreshes a persisted user session row.
func UpsertUserSessionRow(row *UserSessionRow) error {
	if row == nil {
		return nil
	}
	return DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "session_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"device_id", "device_name", "ip", "user_agent",
			"status", "expires_at", "last_active_at",
		}),
	}).Create(row).Error
}

// RevokeSessionRow marks one persisted session revoked (either identity type).
// Revoking an unknown/expired row is a no-op.
func RevokeSessionRow(sessionID string) error {
	now := time.Now().Unix()
	adminErr := DB.Model(&AdminSessionRow{}).
		Where("session_id = ? AND status = ?", sessionID, SessionRowActive).
		Updates(map[string]interface{}{"status": SessionRowRevoked, "last_active_at": now}).Error
	if adminErr != nil {
		return adminErr
	}
	return DB.Model(&UserSessionRow{}).
		Where("session_id = ? AND status = ?", sessionID, SessionRowActive).
		Updates(map[string]interface{}{"status": SessionRowRevoked, "last_active_at": now}).Error
}

// RevokeAllSessionRowsFor marks every active session of an account revoked.
// subject selects the table ("admin" / "user"); accountID is the admin/user id.
func RevokeAllSessionRowsFor(subject string, accountID int64) error {
	now := time.Now().Unix()
	updates := map[string]interface{}{"status": SessionRowRevoked, "last_active_at": now}
	if subject == constants.AdminSubject {
		return DB.Model(&AdminSessionRow{}).
			Where("account_id = ? AND status = ?", accountID, SessionRowActive).
			Updates(updates).Error
	}
	return DB.Model(&UserSessionRow{}).
		Where("user_id = ? AND status = ?", accountID, SessionRowActive).
		Updates(updates).Error
}

// ListAdminSessionRows returns an admin's persisted sessions, newest first.
// Expired rows are excluded (they no longer grant access).
func ListAdminSessionRows(accountID int64) ([]*AdminSessionRow, error) {
	var rows []*AdminSessionRow
	err := DB.Where("account_id = ? AND expires_at > ?", accountID, time.Now().Unix()).
		Order("created_at DESC").Find(&rows).Error
	return rows, err
}

// ListUserSessionRows returns a user's persisted sessions, newest first.
func ListUserSessionRows(organizationID, userID int64) ([]*UserSessionRow, error) {
	var rows []*UserSessionRow
	err := DB.Where("organization_id = ? AND user_id = ? AND expires_at > ?", organizationID, userID, time.Now().Unix()).
		Order("created_at DESC").Find(&rows).Error
	return rows, err
}

// DeleteExpiredSessionRows hard-deletes session rows that expired more than
// retentionDays ago, for a periodic cleanup job. Best-effort.
func DeleteExpiredSessionRows(retentionDays int) (int64, error) {
	threshold := time.Now().Unix() - int64(retentionDays)*24*3600
	r1 := DB.Where("expires_at < ?", threshold).Delete(&AdminSessionRow{})
	if r1.Error != nil {
		return 0, r1.Error
	}
	r2 := DB.Where("expires_at < ?", threshold).Delete(&UserSessionRow{})
	return r1.RowsAffected + r2.RowsAffected, r2.Error
}

// AdminSessionRowDAO is the data-access handle for the admin session table.
type AdminSessionRowDAO struct {
	db *gorm.DB
}

// NewAdminSessionRowDAO builds an AdminSessionRowDAO bound to the connection.
func NewAdminSessionRowDAO(db *gorm.DB) *AdminSessionRowDAO {
	return &AdminSessionRowDAO{db: db}
}

// UserSessionRowDAO is the data-access handle for the user session table.
type UserSessionRowDAO struct {
	db *gorm.DB
}

// NewUserSessionRowDAO builds a UserSessionRowDAO bound to the connection.
func NewUserSessionRowDAO(db *gorm.DB) *UserSessionRowDAO {
	return &UserSessionRowDAO{db: db}
}
