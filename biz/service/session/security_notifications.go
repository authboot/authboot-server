package session

import (
	"context"
	"time"

	"github.com/authboot/authboot-server/pkg/securitymetrics"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/email"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const securityNotificationTimeout = 10 * time.Second
const securityNotificationLease = 5 * time.Minute

func securityRowLock() clause.Locking { return clause.Locking{Strength: "UPDATE"} }
func securityLog(ctx context.Context, operation string, err error) {
	hlog.CtxWarnf(ctx, "security center %s failed: %v", operation, err)
}

// RetrySecurityNotifications sends at most three due messages per invocation.
// Login calls it after committing events. A lease and bounded attempts permit
// later logins to retry failures without promising exactly-once delivery.
func RetrySecurityNotifications(ctx context.Context, org, user int64) {
	retrySecurityNotifications(ctx, org, user, func(ctx context.Context, msg *email.Message) error {
		return email.SendFor(ctx, org, msg)
	})
}
func retrySecurityNotifications(ctx context.Context, org, user int64, send func(context.Context, *email.Message) error) {
	var events []db.UserSecurityEvent
	now := time.Now().Unix()
	if err := db.DB.Model(&db.UserSecurityEvent{}).Where("organization_id = ? AND user_id = ? AND notify_status = ? AND notify_attempts >= ? AND notify_after <= ?", org, user, "pending", 3, now).Update("notify_status", "failed").Error; err != nil {
		securityLog(ctx, "expire notification lease", err)
	}
	if err := db.DB.Where("organization_id = ? AND user_id = ? AND notify_status = ? AND notify_attempts < ? AND notify_after <= ?", org, user, "pending", 3, now).Order("created_at").Limit(3).Find(&events).Error; err != nil {
		securityLog(ctx, "load notifications", err)
		return
	}
	for _, e := range events {
		claimTime := time.Now()
		result := db.DB.Model(&db.UserSecurityEvent{}).Where("id = ? AND notify_status = ? AND notify_attempts = ? AND notify_after <= ?", e.ID, "pending", e.NotifyAttempts, claimTime.Unix()).Updates(map[string]interface{}{"notify_attempts": gorm.Expr("notify_attempts + 1"), "notify_after": claimTime.Add(securityNotificationLease).Unix()})
		if result.Error != nil {
			securityLog(ctx, "claim notification", result.Error)
			continue
		}
		if result.RowsAffected != 1 {
			continue
		}
		identities, err := db.NewUserIdentityDAO(db.DB).ListIdentitiesByUserInOrg(org, user)
		status := "pending"
		if err == nil {
			address := ""
			for _, identity := range identities {
				if identity.IdentityType == "email" {
					address = identity.IdentityValue
					break
				}
			}
			if address == "" {
				status = "no_email"
			} else {
				// Bound from claim time, so slow DB lookups cannot move sending
				// beyond the lease and overlap a subsequent attempt.
				sendCtx, cancel := context.WithDeadline(ctx, claimTime.Add(securityNotificationTimeout))
				var subject, html string
				subject, html, err = email.RenderFor(sendCtx, org, "security_alert", map[string]any{
					"Kind":     e.Kind,
					"Time":     time.Unix(e.CreatedAt, 0).UTC().Format(time.RFC3339),
					"IP":       e.IP,
					"Location": e.Location.Display,
				})
				if err == nil {
					err = send(sendCtx, &email.Message{To: []string{address}, Subject: subject, HTML: html})
				}
				cancel()
				if err == nil {
					status = "sent"
				}
			}
		}
		if err != nil {
			securityLog(ctx, "send notification", err)
			securitymetrics.Add("notification_failure_total", 1)
			if e.NotifyAttempts+1 >= 3 {
				status = "failed"
			}
		}
		if err := db.DB.Model(&db.UserSecurityEvent{}).Where("id = ? AND notify_attempts = ?", e.ID, e.NotifyAttempts+1).Update("notify_status", status).Error; err != nil {
			securityLog(ctx, "finish notification", err)
		}
	}
}
