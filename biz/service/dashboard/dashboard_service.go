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

// Package dashboard serves the admin web console's dashboard figures: an
// org-scoped console (KPI cards, 6-month login chart, recent users, daily
// trends) and a platform-wide console (organizations / users / admins / audit
// volume).
package dashboard

import (
	"context"
	"math"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/model/dashboard"
	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/authboot/authboot-server/pkg/utils"
)

// recentUsersLimit is how many entries the dashboard's "recent users" list
// returns.
const recentUsersLimit = 5

// DashboardService aggregates read-only statistics for the admin dashboard.
type DashboardService struct {
	ctx context.Context
	c   *app.RequestContext

	userIdentityDAO *db.UserIdentityDAO
}

// NewDashboardService creates a dashboard statistics service.
func NewDashboardService(ctx context.Context, c *app.RequestContext) *DashboardService {
	return &DashboardService{
		ctx:             ctx,
		c:               c,
		userIdentityDAO: db.NewUserIdentityDAO(db.DB),
	}
}

// OrgDashboard aggregates the org console numbers. The first block matches the
// dashboard UI: four KPI cards (total users / new this month / active this
// month / login success rate, each with a month-over-month delta), a two-series
// 6-month login chart, and the latest registered users.
//
// Round trips: the metric families are folded into combined SUM(CASE WHEN)
// queries, so one dashboard load costs 8 queries (user KPIs, login KPIs,
// active KPIs, daily login trend, new-user trend, admin count, recent users,
// recent-user identities) instead of one query per number.
func (s *DashboardService) OrgDashboard(orgID int64) (*dashboard.OrgDashboardResponse, error) {
	if orgID == 0 {
		return nil, errno.ParamErr
	}
	now := time.Now()
	today, weekStart := dashboardWindows()
	monthStartT := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	lastMonthStartT := monthStartT.AddDate(0, -1, 0)
	monthStart, lastMonthStart := monthStartT.Unix(), lastMonthStartT.Unix()
	chartStart := monthStartT.AddDate(0, -5, 0).Unix() // 6 months incl. current
	until := now.Unix() + 1                          // exclusive upper bound

	// 1. user-card and user-count numbers in one pass over tb_users.
	userKPIs, err := db.QueryUserKPIs(orgID, today, monthStart, lastMonthStart, until)
	if err != nil {
		return nil, err
	}
	// 2. today / this-month / last-month login outcomes in one pass.
	loginKPIs, err := db.QueryLoginKPIs(orgID, today, monthStart, lastMonthStart, until)
	if err != nil {
		return nil, err
	}
	// 3. distinct active users (7d / this month / last month) in one pass.
	activeSince := weekStart
	if lastMonthStart < activeSince {
		activeSince = lastMonthStart
	}
	activeKPIs, err := db.QueryActiveUserKPIs(orgID, activeSince, weekStart, monthStart, lastMonthStart, until)
	if err != nil {
		return nil, err
	}
	// 4. one daily series over 6 months feeds both the 7-day trend and the
	//    monthly chart (aggregated below), avoiding a third trend query.
	dailyLogins, err := db.DailyLoginTrendInOrg(orgID, chartStart)
	if err != nil {
		return nil, err
	}
	// 5. new-user daily trend (different table, cannot fold into the above).
	newUserTrend, err := db.NewUserTrendInOrg(orgID, weekStart)
	if err != nil {
		return nil, err
	}
	// 6. admin count.
	adminCount, err := db.CountAdminsInOrg(orgID)
	if err != nil {
		return nil, err
	}
	// 7+8. latest users and their identities (batch, no N+1).
	recentUsers, err := s.recentUsers(orgID)
	if err != nil {
		return nil, err
	}

	successRate := percent(loginKPIs.MonthSuccess, loginKPIs.MonthSuccess+loginKPIs.MonthFailed)
	lastSuccessRate := percent(loginKPIs.LastMonthSuccess, loginKPIs.LastMonthSuccess+loginKPIs.LastMonthFailed)
	weekStartDate := time.Unix(weekStart, 0).Format("2006-01-02")

	return &dashboard.OrgDashboardResponse{
		Code:                  errno.SuccessCode,
		Message:               errno.SuccessMsg,
		TotalUsers:            userKPIs.Total,
		TodayNewUsers:         userKPIs.TodayNew,
		ActiveUsers_7D:        activeKPIs.Active7d,
		DisabledUsers:         userKPIs.Disabled,
		AdminCount:            adminCount,
		TodayLogins:           loginKPIs.TodaySuccess,
		TodayFailedLogins:     loginKPIs.TodayFailed,
		LoginTrend_7D:         successTrendSince(dailyLogins, weekStartDate),
		NewUserTrend_7D:       toTrendPoints(newUserTrend),
		NewUsersThisMonth:     userKPIs.ThisMonthNew,
		NewUsersDeltaPct:      pctChange(userKPIs.ThisMonthNew, userKPIs.LastMonthNew),
		ActiveUsersThisMonth:  activeKPIs.ActiveThisMonth,
		ActiveUsersDeltaPct:   pctChange(activeKPIs.ActiveThisMonth, activeKPIs.ActiveLastMonth),
		TotalUsersDeltaPct:    pctChange(userKPIs.ThisMonthNew, userKPIs.BeforeMonth),
		LoginSuccessRate:      successRate,
		LoginSuccessRateDelta: round1(successRate - lastSuccessRate),
		MonthlyLoginTrend:     monthlyLoginTrend(dailyLogins),
		RecentUsers:           recentUsers,
	}, nil
}

// recentUsers returns the newest users with a masked preferred contact
// (email, else phone) for the dashboard's right-hand list.
func (s *DashboardService) recentUsers(orgID int64) ([]*dashboard.RecentUser, error) {
	users, err := db.ListRecentUsersInOrg(orgID, recentUsersLimit)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return []*dashboard.RecentUser{}, nil
	}
	userIDs := make([]int64, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.ID)
	}
	identities, err := s.userIdentityDAO.ListIdentitiesByUserIDs(orgID, userIDs)
	if err != nil {
		return nil, err
	}
	// Pick the most useful contact per user: email, then phone, then anything.
	best := map[int64]*db.UserIdentity{}
	for _, id := range identities {
		cur, ok := best[id.UserID]
		if !ok || identityRank(id.IdentityType) < identityRank(cur.IdentityType) {
			best[id.UserID] = id
		}
	}
	out := make([]*dashboard.RecentUser, 0, len(users))
	for _, u := range users {
		identity := ""
		if id, ok := best[u.ID]; ok {
			identity = utils.MaskContact(id.IdentityValue)
		}
		out = append(out, &dashboard.RecentUser{
			UserId:    u.ID,
			Nickname:  u.UserName,
			Avatar:    u.Avatar,
			Identity:  identity,
			CreatedAt: u.CreatedAt,
		})
	}
	return out, nil
}

// PlatformDashboard aggregates the platform console numbers across all
// organizations.
func (s *DashboardService) PlatformDashboard() (*dashboard.PlatformDashboardResponse, error) {
	today, _ := dashboardWindows()
	success := true

	orgCount, err := db.CountOrganizations()
	if err != nil {
		return nil, err
	}
	userCount, err := db.CountAllUsers()
	if err != nil {
		return nil, err
	}
	adminCount, err := db.CountAdminUsers()
	if err != nil {
		return nil, err
	}
	auditCount, err := db.CountAuditLogs()
	if err != nil {
		return nil, err
	}
	todayLogins, err := db.CountLoginsSince(today, &success)
	if err != nil {
		return nil, err
	}
	todayNewUsers, err := db.CountUsersCreatedSince(today)
	if err != nil {
		return nil, err
	}

	return &dashboard.PlatformDashboardResponse{
		Code:              errno.SuccessCode,
		Message:           errno.SuccessMsg,
		OrganizationCount: orgCount,
		UserCount:         userCount,
		AdminCount:        adminCount,
		AuditLogCount:     auditCount,
		TodayLoginCount:   todayLogins,
		TodayNewUsers:     todayNewUsers,
	}, nil
}

// dashboardWindows returns the start-of-today and start-of-6-days-ago unix
// timestamps (a rolling 7-day window including today).
func dashboardWindows() (today, weekStart int64) {
	now := time.Now()
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	return startOfToday.Unix(), startOfToday.AddDate(0, 0, -6).Unix()
}

// toTrendPoints maps DAL trend rows to the proto view.
func toTrendPoints(rows []db.TrendRow) []*dashboard.TrendPoint {
	points := make([]*dashboard.TrendPoint, 0, len(rows))
	for _, r := range rows {
		points = append(points, &dashboard.TrendPoint{Date: r.Date, Count: r.Count})
	}
	return points
}

// successTrendSince extracts successful-login points from the daily rows from
// sinceDate onward (YYYY-MM-DD strings compare lexicographically).
func successTrendSince(rows []db.DailyLoginRow, sinceDate string) []*dashboard.TrendPoint {
	points := make([]*dashboard.TrendPoint, 0, len(rows))
	for _, r := range rows {
		if r.Date >= sinceDate {
			points = append(points, &dashboard.TrendPoint{Date: r.Date, Count: r.Success})
		}
	}
	return points
}

// monthlyLoginTrend aggregates daily rows into calendar months. Rows arrive
// oldest-first, so the output stays chronological.
func monthlyLoginTrend(rows []db.DailyLoginRow) []*dashboard.MonthlyLoginTrend {
	byMonth := make(map[string]*dashboard.MonthlyLoginTrend, 6)
	order := make([]string, 0, 6)
	for _, r := range rows {
		if len(r.Date) < 7 {
			continue
		}
		month := r.Date[:7]
		p, ok := byMonth[month]
		if !ok {
			p = &dashboard.MonthlyLoginTrend{Month: month}
			byMonth[month] = p
			order = append(order, month)
		}
		p.Success += r.Success
		p.Failed += r.Failed
	}
	out := make([]*dashboard.MonthlyLoginTrend, 0, len(order))
	for _, month := range order {
		out = append(out, byMonth[month])
	}
	return out
}

// identityRank orders identities for the recent-users list: email first, then
// phone, then anything else.
func identityRank(t string) int {
	switch t {
	case constants.IdentityTypeEmail:
		return 0
	case constants.IdentityTypePhone:
		return 1
	default:
		return 2
	}
}

// pctChange returns the percentage change from prev to cur: 0 when both are 0,
// 100 when prev is 0 and cur > 0, otherwise (cur-prev)/prev*100. One decimal.
func pctChange(cur, prev int64) float64 {
	if prev == 0 {
		if cur == 0 {
			return 0
		}
		return 100
	}
	return round1(float64(cur-prev) / float64(prev) * 100)
}

// percent returns part/total*100 rounded to one decimal (0 when total is 0).
func percent(part, total int64) float64 {
	if total == 0 {
		return 0
	}
	return round1(float64(part) / float64(total) * 100)
}

// round1 rounds to one decimal place.
func round1(v float64) float64 {
	return math.Round(v*10) / 10
}
