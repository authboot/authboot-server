package securityops

import (
	"context"
	"time"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/securitymetrics"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RunRetention selects bounded primary-key batches and repeats the eligibility
// predicate on DELETE. It never removes active mirrors or unresolved events.
func (w *Worker) RunRetention(ctx context.Context, now time.Time) (int64, error) {
	days := w.Config.RetentionDays
	if days < 30 {
		days = 180
	}
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
	type policy struct {
		table, key, where string
		args              []any
	}
	policies := []policy{
		{(db.AdminLoginLog{}).TableName(), "id", "created_at < ?", []any{cutoff.Unix()}},
		{(db.UserLoginLog{}).TableName(), "id", "created_at < ?", []any{cutoff.Unix()}},
		{(db.AdminAuditLog{}).TableName(), "id", "created_at < ?", []any{cutoff}},
		{(db.UserAuditLog{}).TableName(), "id", "created_at < ?", []any{cutoff.Unix()}},
		{(db.UserSecurityEvent{}).TableName(), "id", "resolved_at > 0 AND resolved_at < ? AND status <> 'pending' AND notify_status NOT IN ('pending','sending','retry')", []any{cutoff.Unix()}},
		{(db.AdminSessionRow{}).TableName(), "id", "status = 2 AND expires_at < ?", []any{cutoff.Unix()}},
		{(db.UserSessionRow{}).TableName(), "id", "status = 2 AND expires_at < ?", []any{cutoff.Unix()}},
		{(db.SecurityGrant{}).TableName(), "hash", "expires_at < ?", []any{now.Unix()}},
		{(db.AdminMFAChallenge{}).TableName(), "hash", "expires_at < ?", []any{now.Unix()}},
		{(db.AdminMFA{}).TableName(), "account_id", "enabled = false AND setup_expires_at > 0 AND setup_expires_at < ?", []any{now.Unix()}},
		{(db.RevocationOutbox{}).TableName(), "id", "completed_at > 0 AND completed_at < ?", []any{cutoff.Unix()}},
	}
	var total int64
	for _, p := range policies {
		conn := w.DB.WithContext(ctx).Table(p.table)
		var keys []string
		if err := conn.Where(p.where, p.args...).Order(p.key).Limit(w.batch()).Pluck(p.key, &keys).Error; err != nil {
			return total, err
		}
		securitymetrics.Add("retention_candidate_total", int64(len(keys)))
		if w.Config.DryRun || len(keys) == 0 {
			continue
		}
		result := conn.Where(p.key+" IN ?", keys).Where(p.where, p.args...).Delete(map[string]any{})
		if result.Error != nil {
			return total, result.Error
		}
		total += result.RowsAffected
		securitymetrics.Add("retention_deleted_total", result.RowsAffected)
	}
	devices, err := w.cleanDevices(ctx, cutoff.Unix())
	return total + devices, err
}

func (w *Worker) cleanDevices(ctx context.Context, cutoff int64) (int64, error) {
	w.deviceScanMu.Lock()
	defer w.deviceScanMu.Unlock()
	if w.deviceCursors == nil {
		w.deviceCursors = make(map[string]int64)
	}
	var total int64
	for _, subject := range []string{"admin", "user"} {
		table, account := (db.AdminDevice{}).TableName(), "account_id"
		if subject == "user" {
			table, account = (db.UserDevice{}).TableName(), "user_id"
		}
		var rows []struct {
			ID, AccountID int64
			DeviceID      string
		}
		query := w.DB.WithContext(ctx).Table(table).
			Select("id, "+account+" AS account_id, device_id").
			Where("id > ? AND last_used_at < ?", w.deviceCursors[subject], cutoff)
		if subject == "user" {
			query = query.Where("last_active_at < ?", cutoff)
		}
		if err := query.Order("id").Limit(w.batch()).Scan(&rows).Error; err != nil {
			return total, err
		}
		for _, row := range rows {
			err := w.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				// Session creation uses the same account lock. Redis unavailability
				// aborts cleanup rather than assuming no active device.
				if subject == "user" {
					var owner db.User
					if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&owner, row.AccountID).Error; err != nil {
						return err
					}
				} else {
					var owner db.AdminUser
					if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&owner, row.AccountID).Error; err != nil {
						return err
					}
				}
				sessions, err := (redis.SessionStore{}).ListForUser(subject, row.AccountID)
				if err != nil {
					return err
				}
				for _, session := range sessions {
					if session.DeviceID == row.DeviceID {
						return nil
					}
				}
				securitymetrics.Add("retention_candidate_total", 1)
				if w.Config.DryRun {
					return nil
				}
				q := tx.Table(table).Where("id = ? AND last_used_at < ?", row.ID, cutoff)
				if subject == "user" {
					q = q.Where("last_active_at < ?", cutoff)
				}
				result := q.Delete(map[string]any{})
				if result.Error != nil {
					return result.Error
				}
				total += result.RowsAffected
				securitymetrics.Add("retention_deleted_total", result.RowsAffected)
				return nil
			})
			if err != nil {
				return total, err
			}
			// Successful inspection advances even when Redis says active or
			// dry-run suppresses deletion. Errors leave this row for retry.
			w.deviceCursors[subject] = row.ID
		}
		if len(rows) < w.batch() {
			// End reached. Start a new pass next round, never scan more than
			// one bounded batch per subject in the current round.
			w.deviceCursors[subject] = 0
		}
	}
	return total, nil
}
