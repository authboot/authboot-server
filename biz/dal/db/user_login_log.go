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
	"github.com/authboot/authboot-server/pkg/constants"
	"gorm.io/gorm"
)

// UserLoginLog is an append-only record of an end-user login attempt (who, by
// which identity, from where/which device, and the outcome). Unlike the admin
// audit table this is scoped to App users. IdentityValue is stored MASKED (e.g.
// 138****1234) so login history does not become a raw PII dump; the IP + masked
// identity + outcome are enough for abnormal-login analysis.
type UserLoginLog struct {
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`
	// Composite index for the dashboard's org-scoped aggregates and the login
	// log / abnormal queries: (organization_id, created_at, success, user_id)
	// serves both time-window SUM(CASE WHEN success ...) counts and the
	// COUNT(DISTINCT user_id) active-user counts as a covering index.
	OrganizationID int64  `json:"organization_id" gorm:"column:organization_id;not null;index;index:idx_login_org_created,priority:1"`
	UserID         int64  `json:"user_id" gorm:"column:user_id;not null;default:0;index;index:idx_login_org_created,priority:4"`
	IdentityType   string `json:"identity_type" gorm:"column:identity_type;type:varchar(32)"`
	IdentityValue  string `json:"identity_value" gorm:"column:identity_value;type:varchar(255)"`
	ClientID       int64  `json:"client_id" gorm:"column:client_id"`
	DeviceID       string `json:"device_id" gorm:"column:device_id;type:varchar(64)"`
	DeviceName     string `json:"device_name" gorm:"column:device_name;type:varchar(128)"`
	IP             string `json:"ip" gorm:"column:ip;type:varchar(64)"`
	UserAgent      string `json:"user_agent" gorm:"column:user_agent;type:varchar(255)"`
	Success        bool   `json:"success" gorm:"column:success;not null;default:0;index;index:idx_login_org_created,priority:3"`
	ErrMsg         string `json:"err_msg" gorm:"column:err_msg;type:varchar(255)"`
	CreatedAt      int64  `json:"created_at" gorm:"column:created_at;autoCreateTime;index;index:idx_login_org_created,priority:2"`
}

// TableName defines the table name for the UserLoginLog struct.
func (UserLoginLog) TableName() string { return constants.UserLoginLogTableName }

// InsertUserLoginLog appends one login-log row. Callers treat it as
// best-effort: a failure is logged by the caller, never surfaced to the client.
func InsertUserLoginLog(log *UserLoginLog) error {
	if log == nil {
		return nil
	}
	return DB.Create(log).Error
}

// UserLoginLogDAO is the data-access handle for the login log table. It wraps a
// *gorm.DB so the same methods run on the global connection (via the package
// default instance) or inside a transaction (via WithTx).
type UserLoginLogDAO struct {
	db *gorm.DB
}

// NewUserLoginLogDAO builds a UserLoginLogDAO bound to the given connection.
func NewUserLoginLogDAO(db *gorm.DB) *UserLoginLogDAO {
	return &UserLoginLogDAO{db: db}
}

// WithTx returns a UserLoginLogDAO that runs its queries on the given transaction.
func (d *UserLoginLogDAO) WithTx(tx *gorm.DB) *UserLoginLogDAO {
	return &UserLoginLogDAO{db: tx}
}

// Insert appends one login-log row through the DAO connection (global or tx).
func (d *UserLoginLogDAO) Insert(log *UserLoginLog) error {
	if log == nil {
		return nil
	}
	return d.db.Create(log).Error
}

// UserLoginLogFilter narrows a login-log query. A zero value for a field means
// "no constraint"; Success is 0=all, 1=success, 2=failed.
type UserLoginLogFilter struct {
	UserID       int64
	IdentityType string
	Success      int32
	StartTime    int64 // unix seconds, lower bound on created_at
	EndTime      int64 // unix seconds, upper bound on created_at
}

// QueryUserLoginLogs returns a filtered page of an organization's user login
// logs, newest first, plus the total matching count.
func QueryUserLoginLogs(organizationID int64, f UserLoginLogFilter, offset, limit int) ([]*UserLoginLog, int64, error) {
	q := DB.Model(&UserLoginLog{}).Where("organization_id = ?", organizationID)
	if f.UserID != 0 {
		q = q.Where("user_id = ?", f.UserID)
	}
	if f.IdentityType != "" {
		q = q.Where("identity_type = ?", f.IdentityType)
	}
	switch f.Success {
	case 1:
		q = q.Where("success = ?", true)
	case 2:
		q = q.Where("success = ?", false)
	}
	if f.StartTime != 0 {
		q = q.Where("created_at >= ?", f.StartTime)
	}
	if f.EndTime != 0 {
		q = q.Where("created_at <= ?", f.EndTime)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var logs []*UserLoginLog
	if err := q.Order("id DESC").Offset(offset).Limit(limit).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// FailedLoginGroup is one account's failed-login count within a window, used by
// the abnormal-login alarm. IPs is the distinct source IPs, comma-separated.
type FailedLoginGroup struct {
	UserID        int64  `gorm:"column:user_id"`
	IdentityValue string `gorm:"column:identity_value"`
	FailedCount   int64  `gorm:"column:failed_count"`
	IPs           string `gorm:"column:ip_addresses"`
}

// CountFailedLoginsGrouped returns accounts with at least threshold failed
// logins since `since` (unix seconds), newest accounts first — the brute-force /
// credential-stuffing signal surfaced by the abnormal-login endpoint.
func CountFailedLoginsGrouped(organizationID int64, since int64, threshold int) ([]FailedLoginGroup, error) {
	var groups []FailedLoginGroup
	err := DB.Model(&UserLoginLog{}).
		Select("user_id, identity_value, COUNT(*) AS failed_count, GROUP_CONCAT(DISTINCT ip) AS ip_addresses").
		Where("organization_id = ? AND success = ? AND created_at >= ?", organizationID, false, since).
		Group("user_id, identity_value").
		Having("COUNT(*) >= ?", threshold).
		Order("failed_count DESC").
		Scan(&groups).Error
	return groups, err
}
