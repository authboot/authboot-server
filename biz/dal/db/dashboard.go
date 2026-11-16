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

// TrendRow is one day's count for a dashboard trend series.
type TrendRow struct {
	Date  string `gorm:"column:date"`
	Count int64  `gorm:"column:cnt"`
}

// ---------------------------------------------------------------------------
// org-scoped aggregates (one organization's console numbers)
// ---------------------------------------------------------------------------

// CountUsersInOrg returns the total number of App users in an organization.
func CountUsersInOrg(orgID int64) (int64, error) {
	var c int64
	err := DB.Model(&User{}).Where("organization_id = ?", orgID).Count(&c).Error
	return c, err
}

// CountUsersByStatusInOrg returns users of a given status (enabled/disabled).
func CountUsersByStatusInOrg(orgID int64, status int8) (int64, error) {
	var c int64
	err := DB.Model(&User{}).Where("organization_id = ? AND status = ?", orgID, status).Count(&c).Error
	return c, err
}

// CountUsersCreatedSinceInOrg returns users created since a unix timestamp.
func CountUsersCreatedSinceInOrg(orgID, since int64) (int64, error) {
	var c int64
	err := DB.Model(&User{}).Where("organization_id = ? AND created_at >= ?", orgID, since).Count(&c).Error
	return c, err
}

// CountAdminsInOrg returns the number of enabled admin memberships (admins
// who have joined the organization console).
func CountAdminsInOrg(orgID int64) (int64, error) {
	var c int64
	err := DB.Model(&OrganizationMembership{}).
		Where("organization_id = ? AND status = ?", orgID, constants.StatusEnabled).
		Count(&c).Error
	return c, err
}

// CountActiveUsersInOrgSince returns distinct users who logged in successfully
// at least once since a unix timestamp.
func CountActiveUsersInOrgSince(orgID, since int64) (int64, error) {
	var c int64
	err := DB.Model(&UserLoginLog{}).
		Where("organization_id = ? AND success = ? AND created_at >= ?", orgID, true, since).
		Distinct("user_id").Count(&c).Error
	return c, err
}

// CountLoginsInOrg counts login attempts since a unix timestamp; success=nil
// counts all, true/false filter by outcome.
func CountLoginsInOrg(orgID, since int64, success *bool) (int64, error) {
	var c int64
	q := DB.Model(&UserLoginLog{}).Where("organization_id = ? AND created_at >= ?", orgID, since)
	if success != nil {
		q = q.Where("success = ?", *success)
	}
	err := q.Count(&c).Error
	return c, err
}

// LoginTrendInOrg returns per-day successful-login counts (newest-last), used
// for the org console login trend chart.
func LoginTrendInOrg(orgID, since int64) ([]TrendRow, error) {
	return dailyTrend(DB.Model(&UserLoginLog{}).Where("organization_id = ? AND success = ?", orgID, true), since)
}

// NewUserTrendInOrg returns per-day user-creation counts (newest-last), used
// for the org console growth chart.
func NewUserTrendInOrg(orgID, since int64) ([]TrendRow, error) {
	return dailyTrend(DB.Model(&User{}).Where("organization_id = ?", orgID), since)
}

// CountUsersBeforeInOrg returns the user population created before a unix
// timestamp — i.e. the population at the start of a period.
func CountUsersBeforeInOrg(orgID, before int64) (int64, error) {
	var c int64
	err := DB.Model(&User{}).
		Where("organization_id = ? AND created_at < ?", orgID, before).Count(&c).Error
	return c, err
}

// CountUsersCreatedBetweenInOrg counts users created in [from, to).
func CountUsersCreatedBetweenInOrg(orgID, from, to int64) (int64, error) {
	var c int64
	err := DB.Model(&User{}).
		Where("organization_id = ? AND created_at >= ? AND created_at < ?", orgID, from, to).
		Count(&c).Error
	return c, err
}

// CountActiveUsersInOrgBetween returns distinct users with a successful login
// in [from, to).
func CountActiveUsersInOrgBetween(orgID, from, to int64) (int64, error) {
	var c int64
	err := DB.Model(&UserLoginLog{}).
		Where("organization_id = ? AND success = ? AND created_at >= ? AND created_at < ?", orgID, true, from, to).
		Distinct("user_id").Count(&c).Error
	return c, err
}

// CountLoginsInOrgBetween counts login attempts in [from, to); success=nil
// counts all, true/false filter by outcome.
func CountLoginsInOrgBetween(orgID, from, to int64, success *bool) (int64, error) {
	var c int64
	q := DB.Model(&UserLoginLog{}).
		Where("organization_id = ? AND created_at >= ? AND created_at < ?", orgID, from, to)
	if success != nil {
		q = q.Where("success = ?", *success)
	}
	err := q.Count(&c).Error
	return c, err
}

// MonthlyLoginRow is one month's successful/failed login counts.
type MonthlyLoginRow struct {
	Month   string `gorm:"column:month"`
	Success int64  `gorm:"column:success_cnt"`
	Failed  int64  `gorm:"column:failed_cnt"`
}

// MonthlyLoginTrendInOrg returns per-month successful/failed login counts
// since a unix timestamp (oldest-first), feeding the dashboard's two-series
// line chart.
func MonthlyLoginTrendInOrg(orgID, since int64) ([]MonthlyLoginRow, error) {
	var rows []MonthlyLoginRow
	err := DB.Model(&UserLoginLog{}).
		Select("DATE_FORMAT(FROM_UNIXTIME(created_at), '%Y-%m') AS month, " +
			"SUM(CASE WHEN success THEN 1 ELSE 0 END) AS success_cnt, " +
			"SUM(CASE WHEN success THEN 0 ELSE 1 END) AS failed_cnt").
		Where("organization_id = ? AND created_at >= ?", orgID, since).
		Group("month").
		Order("month ASC").
		Scan(&rows).Error
	return rows, err
}

// ListRecentUsersInOrg returns the newest users in an organization (by id desc).
func ListRecentUsersInOrg(orgID int64, limit int) ([]*User, error) {
	if limit <= 0 {
		limit = 5
	}
	var users []*User
	err := DB.Where("organization_id = ?", orgID).Order("id DESC").Limit(limit).Find(&users).Error
	return users, err
}

// ---------------------------------------------------------------------------
// combined aggregates: one query per metric family instead of one per number,
// so a dashboard load costs ~8 round trips instead of ~21.
// ---------------------------------------------------------------------------

// UserKPI holds all user-card numbers of the org dashboard in one row.
type UserKPI struct {
	Total        int64 `gorm:"column:total"`
	Disabled     int64 `gorm:"column:disabled"`
	TodayNew     int64 `gorm:"column:today_new"`
	ThisMonthNew int64 `gorm:"column:this_month_new"`
	LastMonthNew int64 `gorm:"column:last_month_new"`
	BeforeMonth  int64 `gorm:"column:before_month"` // population at the start of this month
}

// QueryUserKPIs computes the user-card numbers in a single pass over the
// organization's users. Windows: [today, now], [monthStart, until),
// [lastMonthStart, monthStart), (< monthStart).
func QueryUserKPIs(orgID, today, monthStart, lastMonthStart, until int64) (*UserKPI, error) {
	var k UserKPI
	err := DB.Model(&User{}).
		Select(`COUNT(*) AS total,
			COALESCE(SUM(CASE WHEN status = ? THEN 1 ELSE 0 END), 0) AS disabled,
			COALESCE(SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END), 0) AS today_new,
			COALESCE(SUM(CASE WHEN created_at >= ? AND created_at < ? THEN 1 ELSE 0 END), 0) AS this_month_new,
			COALESCE(SUM(CASE WHEN created_at >= ? AND created_at < ? THEN 1 ELSE 0 END), 0) AS last_month_new,
			COALESCE(SUM(CASE WHEN created_at < ? THEN 1 ELSE 0 END), 0) AS before_month`,
			constants.StatusDisabled,
			today,
			monthStart, until,
			lastMonthStart, monthStart,
			monthStart).
		Where("organization_id = ?", orgID).
		Scan(&k).Error
	return &k, err
}

// LoginKPI holds all login-card numbers of the org dashboard in one row.
type LoginKPI struct {
	TodaySuccess     int64 `gorm:"column:today_success"`
	TodayFailed      int64 `gorm:"column:today_failed"`
	MonthSuccess     int64 `gorm:"column:month_success"`
	MonthFailed      int64 `gorm:"column:month_failed"`
	LastMonthSuccess int64 `gorm:"column:last_month_success"`
	LastMonthFailed  int64 `gorm:"column:last_month_failed"`
}

// QueryLoginKPIs computes today's and this/last month's login outcome counts
// in one pass over the last two months of login attempts.
func QueryLoginKPIs(orgID, today, monthStart, lastMonthStart, until int64) (*LoginKPI, error) {
	var k LoginKPI
	err := DB.Model(&UserLoginLog{}).
		Select(`COALESCE(SUM(CASE WHEN created_at >= ? AND success THEN 1 ELSE 0 END), 0) AS today_success,
			COALESCE(SUM(CASE WHEN created_at >= ? AND NOT success THEN 1 ELSE 0 END), 0) AS today_failed,
			COALESCE(SUM(CASE WHEN created_at >= ? AND created_at < ? AND success THEN 1 ELSE 0 END), 0) AS month_success,
			COALESCE(SUM(CASE WHEN created_at >= ? AND created_at < ? AND NOT success THEN 1 ELSE 0 END), 0) AS month_failed,
			COALESCE(SUM(CASE WHEN created_at >= ? AND created_at < ? AND success THEN 1 ELSE 0 END), 0) AS last_month_success,
			COALESCE(SUM(CASE WHEN created_at >= ? AND created_at < ? AND NOT success THEN 1 ELSE 0 END), 0) AS last_month_failed`,
			today, today,
			monthStart, until,
			monthStart, until,
			lastMonthStart, monthStart,
			lastMonthStart, monthStart).
		Where("organization_id = ? AND created_at >= ?", orgID, lastMonthStart).
		Scan(&k).Error
	return &k, err
}

// ActiveKPI holds the distinct-active-user numbers of the org dashboard.
type ActiveKPI struct {
	Active7d        int64 `gorm:"column:active_7d"`
	ActiveThisMonth int64 `gorm:"column:active_this_month"`
	ActiveLastMonth int64 `gorm:"column:active_last_month"`
}

// QueryActiveUserKPIs counts distinct users with a successful login in the
// 7-day, this-month and last-month windows in one pass. `since` must be the
// earliest of weekStart and lastMonthStart.
func QueryActiveUserKPIs(orgID, since, weekStart, monthStart, lastMonthStart, until int64) (*ActiveKPI, error) {
	var k ActiveKPI
	err := DB.Model(&UserLoginLog{}).
		Select(`COUNT(DISTINCT CASE WHEN created_at >= ? THEN user_id END) AS active_7d,
			COUNT(DISTINCT CASE WHEN created_at >= ? AND created_at < ? THEN user_id END) AS active_this_month,
			COUNT(DISTINCT CASE WHEN created_at >= ? AND created_at < ? THEN user_id END) AS active_last_month`,
			weekStart,
			monthStart, until,
			lastMonthStart, monthStart).
		Where("organization_id = ? AND success = ? AND created_at >= ?", orgID, true, since).
		Scan(&k).Error
	return &k, err
}

// DailyLoginRow is one day's successful/failed login counts.
type DailyLoginRow struct {
	Date    string `gorm:"column:date"`
	Success int64  `gorm:"column:success_cnt"`
	Failed  int64  `gorm:"column:failed_cnt"`
}

// DailyLoginTrendInOrg returns per-day successful/failed login counts since a
// unix timestamp (oldest-first). One query feeds BOTH the 7-day trend (filter
// by date) and the 6-month chart (aggregate by month prefix in the caller).
func DailyLoginTrendInOrg(orgID, since int64) ([]DailyLoginRow, error) {
	var rows []DailyLoginRow
	err := DB.Model(&UserLoginLog{}).
		Select("DATE_FORMAT(FROM_UNIXTIME(created_at), '%Y-%m-%d') AS date, " +
			"COALESCE(SUM(CASE WHEN success THEN 1 ELSE 0 END), 0) AS success_cnt, " +
			"COALESCE(SUM(CASE WHEN success THEN 0 ELSE 1 END), 0) AS failed_cnt").
		Where("organization_id = ? AND created_at >= ?", orgID, since).
		Group("date").
		Order("date ASC").
		Scan(&rows).Error
	return rows, err
}

// ---------------------------------------------------------------------------
// platform-scoped aggregates (platform console numbers)
// ---------------------------------------------------------------------------

// CountOrganizations returns the total number of organizations.
func CountOrganizations() (int64, error) {
	var c int64
	err := DB.Model(&Organization{}).Count(&c).Error
	return c, err
}

// CountAllUsers returns the total number of App users across all organizations.
func CountAllUsers() (int64, error) {
	var c int64
	err := DB.Model(&User{}).Count(&c).Error
	return c, err
}

// CountAdminUsers returns the total number of platform admin accounts.
func CountAdminUsers() (int64, error) {
	var c int64
	err := DB.Model(&AdminUser{}).Count(&c).Error
	return c, err
}

// CountAuditLogs returns the total number of admin audit rows.
func CountAuditLogs() (int64, error) {
	var c int64
	err := DB.Model(&AdminAuditLog{}).Count(&c).Error
	return c, err
}

// CountLoginsSince counts login attempts across all organizations since a unix
// timestamp; success=nil counts all, true/false filter by outcome.
func CountLoginsSince(since int64, success *bool) (int64, error) {
	var c int64
	q := DB.Model(&UserLoginLog{}).Where("created_at >= ?", since)
	if success != nil {
		q = q.Where("success = ?", *success)
	}
	err := q.Count(&c).Error
	return c, err
}

// CountUsersCreatedSince counts users created since a unix timestamp across
// all organizations.
func CountUsersCreatedSince(since int64) (int64, error) {
	var c int64
	err := DB.Model(&User{}).Where("created_at >= ?", since).Count(&c).Error
	return c, err
}

// dailyTrend is the shared tail for the MySQL per-day grouping: it groups by
// calendar day (server timezone) and returns rows oldest-first.
func dailyTrend(q *gorm.DB, since int64) ([]TrendRow, error) {
	var rows []TrendRow
	err := q.Select("DATE_FORMAT(FROM_UNIXTIME(created_at), '%Y-%m-%d') AS date, COUNT(*) AS cnt").
		Where("created_at >= ?", since).
		Group("date").
		Order("date ASC").
		Scan(&rows).Error
	return rows, err
}
