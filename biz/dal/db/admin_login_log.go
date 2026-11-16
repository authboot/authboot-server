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

// AdminLoginLog is an append-only record of a platform-admin login attempt,
// symmetric to UserLoginLog. AdminID is 0 when the account is unknown (login
// rejected before lookup). Email is stored masked for failed attempts so the
// table is not a raw PII dump.
type AdminLoginLog struct {
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`
	// idx_admin_login_admin: (admin_id, created_at) 供按管理员查历史。
	AdminID    int64  `json:"admin_id" gorm:"column:admin_id;not null;default:0;index:idx_admin_login_admin,priority:1"`
	Email      string `json:"email" gorm:"column:email;type:varchar(255)"`
	DeviceID   string `json:"device_id" gorm:"column:device_id;type:varchar(64)"`
	DeviceName string `json:"device_name" gorm:"column:device_name;type:varchar(128)"`
	IP         string `json:"ip" gorm:"column:ip;type:varchar(64)"`
	UserAgent  string `json:"user_agent" gorm:"column:user_agent;type:varchar(255)"`
	// idx_admin_login_created: (success, created_at) 供时间窗扫描。
	Success bool   `json:"success" gorm:"column:success;not null;default:0;index:idx_admin_login_created,priority:1"`
	ErrMsg  string `json:"err_msg" gorm:"column:err_msg;type:varchar(255)"`
	// 同一 created_at 列同时参与两个复合索引，priority 决定各自列序。
	CreatedAt int64 `json:"created_at" gorm:"column:created_at;autoCreateTime;index:idx_admin_login_created,priority:2;index:idx_admin_login_admin,priority:2"`
}

// TableName defines the table name for the AdminLoginLog struct.
func (AdminLoginLog) TableName() string { return constants.AdminLoginLogTableName }

// InsertAdminLoginLog appends one admin login-log row. Best-effort by
// convention: callers log failures, never surface them to the client.
func InsertAdminLoginLog(log *AdminLoginLog) error {
	if log == nil {
		return nil
	}
	return DB.Create(log).Error
}

// QueryAdminLoginLogs returns a filtered page of admin login logs, newest
// first, plus the total matching count. A zero filter field means "no
// constraint"; Success is 0=all, 1=success, 2=failed.
func QueryAdminLoginLogs(f AdminLoginLogFilter, offset, limit int) ([]*AdminLoginLog, int64, error) {
	q := DB.Model(&AdminLoginLog{})
	if f.AdminID != 0 {
		q = q.Where("admin_id = ?", f.AdminID)
	}
	if f.Email != "" {
		q = q.Where("email = ?", f.Email)
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
	var logs []*AdminLoginLog
	if err := q.Order("id DESC").Offset(offset).Limit(limit).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// AdminLoginLogFilter narrows an admin login-log query.
type AdminLoginLogFilter struct {
	AdminID   int64
	Email     string
	Success   int32
	StartTime int64 // unix seconds, lower bound on created_at
	EndTime   int64 // unix seconds, upper bound on created_at
}

// WithTx returns a DAO handle bound to the given transaction (kept for
// symmetry with the other log DAOs).
func (AdminLoginLogDAO) WithTx(tx *gorm.DB) *AdminLoginLogDAO {
	return &AdminLoginLogDAO{db: tx}
}

// AdminLoginLogDAO is the data-access handle for the admin login log table.
type AdminLoginLogDAO struct {
	db *gorm.DB
}

// NewAdminLoginLogDAO builds an AdminLoginLogDAO bound to the given connection.
func NewAdminLoginLogDAO(db *gorm.DB) *AdminLoginLogDAO {
	return &AdminLoginLogDAO{db: db}
}

// Insert appends one row through the DAO connection (global or tx).
func (d *AdminLoginLogDAO) Insert(log *AdminLoginLog) error {
	if log == nil {
		return nil
	}
	return d.db.Create(log).Error
}
