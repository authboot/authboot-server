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

package service

import (
	"context"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/authboot/authboot-server/biz/dal/db"
)

// defaultAuditPageSize / maxAuditPageSize bound the audit list page size.
const (
	defaultAuditPageSize = 20
	maxAuditPageSize     = 200
)

type AuditService struct {
	ctx context.Context
	c   *app.RequestContext
}

// NewAuditService creates an audit query service.
func NewAuditService(ctx context.Context, c *app.RequestContext) *AuditService {
	return &AuditService{ctx: ctx, c: c}
}

// ListAuditLogs returns a filtered, paginated page of an organization's admin
// audit rows (newest first) plus the total matching count. The generated
// handler maps the returned db rows to the proto AuditLog response.
func (s *AuditService) ListAuditLogs(organizationID int64, f db.AuditLogFilter, page, pageSize int) ([]*db.AdminAuditLog, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = defaultAuditPageSize
	}
	if pageSize > maxAuditPageSize {
		pageSize = maxAuditPageSize
	}
	return db.QueryAuditLogs(organizationID, f, (page-1)*pageSize, pageSize)
}

// ListUserLoginLogs returns a filtered, paginated page of an organization's
// user login logs (newest first) plus the total matching count.
func (s *AuditService) ListUserLoginLogs(organizationID int64, f db.UserLoginLogFilter, page, pageSize int) ([]*db.UserLoginLog, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = defaultAuditPageSize
	}
	if pageSize > maxAuditPageSize {
		pageSize = maxAuditPageSize
	}
	return db.QueryUserLoginLogs(organizationID, f, (page-1)*pageSize, pageSize)
}

// AbnormalLoginSummary returns accounts with at least failedThreshold failed
// logins within the last windowMinutes — the brute-force / credential-stuffing
// signal for the abnormal-login alarm endpoint. Bounds: window 1..1440 minutes
// (default 30), threshold >= 1 (default 5).
func (s *AuditService) AbnormalLoginSummary(organizationID int64, windowMinutes, failedThreshold int) ([]db.FailedLoginGroup, error) {
	if windowMinutes <= 0 {
		windowMinutes = 30
	}
	if windowMinutes > 1440 {
		windowMinutes = 1440
	}
	if failedThreshold < 1 {
		failedThreshold = 5
	}
	since := time.Now().Add(-time.Duration(windowMinutes) * time.Minute).Unix()
	return db.CountFailedLoginsGrouped(organizationID, since, failedThreshold)
}
