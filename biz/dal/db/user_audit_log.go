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
	"gorm.io/gorm"

	"github.com/authboot/authboot-server/pkg/constants"
)

// UserAuditLog is an append-only trail of an App user's SENSITIVE account
// operations (password change/reset, identity bind/unbind, account merge,
// account deletion). Unlike login logs, this is the user-side counterpart of
// the admin audit table. Detail (before/after/extra) is raw JSON the caller
// supplies ALREADY REDACTED — never put passwords, tokens, or secrets here.
type UserAuditLog struct {
	ID             int64  `json:"id" gorm:"primaryKey;autoIncrement"`
	OrganizationID int64  `json:"organization_id" gorm:"column:organization_id;not null;index;index:idx_user_audit_org_created,priority:1"`
	UserID         int64  `json:"user_id" gorm:"column:user_id;not null;default:0;index;index:idx_user_audit_user,priority:2"`
	Action         string `json:"action" gorm:"column:action;type:varchar(64);index"`
	// Resource identifies what the action touched, e.g. "identity:email",
	// "session:<sid>", "password".
	ResourceType string `json:"resource_type" gorm:"column:resource_type;type:varchar(64)"`
	ResourceID   string `json:"resource_id" gorm:"column:resource_id;type:varchar(128)"`
	IP           string `json:"ip" gorm:"column:ip;type:varchar(64)"`
	UserAgent    string `json:"user_agent" gorm:"column:user_agent;type:varchar(255)"`
	Success      bool   `json:"success" gorm:"column:success;not null;default:0"`
	ErrMsg       string `json:"err_msg" gorm:"column:err_msg;type:varchar(512)"`
	Detail       string `json:"detail" gorm:"column:detail;type:json"` // redacted JSON snapshot
	CreatedAt    int64  `json:"created_at" gorm:"column:created_at;autoCreateTime;index;index:idx_user_audit_org_created,priority:2;index:idx_user_audit_user,priority:2"`
}

// TableName defines the table name for the UserAuditLog struct.
func (UserAuditLog) TableName() string { return constants.UserAuditLogTableName }

// UserAuditLogDAO is the data-access handle for the user audit log table.
type UserAuditLogDAO struct {
	db *gorm.DB
}

// NewUserAuditLogDAO builds a UserAuditLogDAO bound to the given connection.
func NewUserAuditLogDAO(db *gorm.DB) *UserAuditLogDAO {
	return &UserAuditLogDAO{db: db}
}

// WithTx returns a UserAuditLogDAO that runs its queries on the given transaction.
func (d *UserAuditLogDAO) WithTx(tx *gorm.DB) *UserAuditLogDAO {
	return &UserAuditLogDAO{db: tx}
}

// Insert appends one audit row through the DAO connection (global or tx).
func (d *UserAuditLogDAO) Insert(log *UserAuditLog) error {
	if log == nil {
		return nil
	}
	return d.db.Create(log).Error
}

// InsertUserAuditLog appends one user audit row. Best-effort by convention:
// callers log failures, never surface them to the client.
func InsertUserAuditLog(log *UserAuditLog) error {
	if log == nil {
		return nil
	}
	return DB.Create(log).Error
}

// QueryUserAuditLogs returns a filtered page of an organization's user audit
// logs, newest first, plus the total matching count. A zero filter field means
// "no constraint".
func QueryUserAuditLogs(organizationID int64, f UserAuditLogFilter, offset, limit int) ([]*UserAuditLog, int64, error) {
	q := DB.Model(&UserAuditLog{}).Where("organization_id = ?", organizationID)
	if f.UserID != 0 {
		q = q.Where("user_id = ?", f.UserID)
	}
	if f.Action != "" {
		q = q.Where("action = ?", f.Action)
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
	var logs []*UserAuditLog
	if err := q.Order("id DESC").Offset(offset).Limit(limit).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// UserAuditLogFilter narrows a user audit-log query.
type UserAuditLogFilter struct {
	UserID    int64
	Action    string
	StartTime int64 // unix seconds, lower bound on created_at
	EndTime   int64 // unix seconds, upper bound on created_at
}
