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

	"github.com/authboot/authboot-server/pkg/constants"
)

// AdminAuditLog is an append-only record of an internal admin action (who did
// what, to which org/resource, when, from where, and the outcome). Rows are
// never updated or deleted. RequestID correlates a row with the access log and,
// when tracing is enabled, TraceID with the distributed trace.
type AdminAuditLog struct {
	ID             int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	RequestID      string    `json:"request_id" gorm:"type:varchar(64);index"`
	TraceID        string    `json:"trace_id" gorm:"type:varchar(64);index"`
	AdminID        int64     `json:"admin_id" gorm:"index"`
	OrganizationID int64     `json:"organization_id" gorm:"index"`
	SessionID      string    `json:"session_id" gorm:"type:varchar(64);index"`
	Action         string    `json:"action" gorm:"type:varchar(64);index"`
	ResourceType   string    `json:"resource_type" gorm:"type:varchar(64)"`
	ResourceID     string    `json:"resource_id" gorm:"type:varchar(128);index"`
	Method         string    `json:"method" gorm:"type:varchar(8)"`
	Path           string    `json:"path" gorm:"type:varchar(255)"`
	IP             string    `json:"ip" gorm:"type:varchar(64)"`
	UserAgent      string    `json:"user_agent" gorm:"type:varchar(255)"`
	Success        bool      `json:"success" gorm:"index"`
	StatusCode     int32     `json:"status_code"`
	ErrMsg         string    `json:"err_msg" gorm:"type:varchar(512)"`
	Before         []byte    `json:"before" gorm:"type:json"`
	After          []byte    `json:"after" gorm:"type:json"`
	Extra          []byte    `json:"extra" gorm:"type:json"`
	LatencyMs      int64     `json:"latency_ms"`
	CreatedAt      time.Time `json:"created_at" gorm:"index;not null"`
}

func (AdminAuditLog) TableName() string {
	return constants.AdminAuditLogTableName
}

// InsertAuditLogs appends a batch of audit rows in one statement. The audit
// writer calls this; it is best-effort from the caller's point of view (a
// failure is logged, not surfaced to the end user's request).
func InsertAuditLogs(logs []*AdminAuditLog) error {
	if len(logs) == 0 {
		return nil
	}
	return DB.Create(&logs).Error
}

// AuditLogFilter narrows an audit query. A zero value for a field means "no
// constraint on that field".
type AuditLogFilter struct {
	AdminID   int64  // only this admin
	Action    string // exact action, e.g. "role.update"
	StartTime int64  // unix seconds, lower bound on created_at
	EndTime   int64  // unix seconds, upper bound on created_at
}

// QueryAuditLogs returns a filtered page of an organization's audit rows,
// newest first, plus the total matching count.
func QueryAuditLogs(organizationID int64, f AuditLogFilter, offset, limit int) ([]*AdminAuditLog, int64, error) {
	q := DB.Model(&AdminAuditLog{}).Where("organization_id = ?", organizationID)
	if f.AdminID != 0 {
		q = q.Where("admin_id = ?", f.AdminID)
	}
	if f.Action != "" {
		q = q.Where("action = ?", f.Action)
	}
	if f.StartTime != 0 {
		q = q.Where("created_at >= ?", time.Unix(f.StartTime, 0))
	}
	if f.EndTime != 0 {
		q = q.Where("created_at <= ?", time.Unix(f.EndTime, 0))
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var logs []*AdminAuditLog
	if err := q.Order("id DESC").Offset(offset).Limit(limit).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}
