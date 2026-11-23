package securityops

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/securitymetrics"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Config struct {
	Interval      time.Duration
	Retention     bool
	DryRun        bool
	RetentionDays int
	Batch         int
}

func FromEnv() (Config, error) {
	c := Config{Interval: 30 * time.Second, Retention: os.Getenv("SECURITY_RETENTION_ENABLED") == "true", DryRun: os.Getenv("SECURITY_RETENTION_DRY_RUN") != "false", RetentionDays: 180, Batch: 200}
	if raw := os.Getenv("SECURITY_RETENTION_DAYS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 30 || n > 3650 {
			return c, errors.New("SECURITY_RETENTION_DAYS must be 30..3650")
		}
		c.RetentionDays = n
	}
	return c, nil
}

type Worker struct {
	DB     *gorm.DB
	Config Config
	Revoke func(subject string, account, org, version int64) error

	// In-memory scan progress is independent per identity domain. Restarting
	// safely rescans from the beginning; concurrent retention calls serialize.
	deviceScanMu  sync.Mutex
	deviceCursors map[string]int64
}

// Start owns exactly one goroutine; stop cancels SQL operations and joins it.
func (w *Worker) Start(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		interval := w.Config.Interval
		if interval <= 0 {
			interval = 30 * time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := w.RunRevocations(ctx, time.Now()); err != nil {
					securitymetrics.Add("worker_failure_total", 1)
					hlog.Error("security revocation worker failed")
				}
				if w.Config.Retention {
					if _, err := w.RunRetention(ctx, time.Now()); err != nil {
						securitymetrics.Add("worker_failure_total", 1)
						hlog.Error("security retention worker failed")
					}
				}
			}
		}
	}()
	return func() { cancel(); <-done }
}

func (w *Worker) batch() int {
	if w.Config.Batch < 1 || w.Config.Batch > 1000 {
		return 200
	}
	return w.Config.Batch
}

func (w *Worker) RunRevocations(ctx context.Context, now time.Time) error {
	conn := w.DB.WithContext(ctx)
	var pending int64
	if err := conn.Model(&db.RevocationOutbox{}).Where("completed_at = 0").Count(&pending).Error; err != nil {
		return err
	}
	securitymetrics.Pending.Store(pending)
	var jobs []db.RevocationOutbox
	if err := conn.Where("completed_at = 0 AND next_attempt_at <= ? AND lease_until <= ?", now.Unix(), now.Unix()).Order("id").Limit(w.batch()).Find(&jobs).Error; err != nil {
		return err
	}
	revoke := w.Revoke
	if revoke == nil {
		revoke = (redis.SessionStore{}).RevokeBeforeVersion
	}
	for _, job := range jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		lease := uuid.NewString()
		claimed := conn.Model(&db.RevocationOutbox{}).Where("id = ? AND completed_at = 0 AND lease_until <= ?", job.ID, now.Unix()).Updates(map[string]any{"lease_until": now.Add(time.Minute).Unix(), "lease_token": lease, "attempts": gorm.Expr("attempts + 1")})
		if claimed.Error != nil {
			return claimed.Error
		}
		if claimed.RowsAffected != 1 {
			continue
		}
		updates := map[string]any{"lease_until": 0, "lease_token": ""}
		if err := revoke(job.Subject, job.AccountID, job.OrganizationID, job.BeforeVersion); err != nil {
			securitymetrics.Add("revocation_failure_total", 1)
			delay := time.Second * time.Duration(1<<min(job.Attempts+1, 10))
			updates["next_attempt_at"] = now.Add(delay).Unix()
		} else {
			updates["completed_at"] = now.Unix()
		}
		if err := conn.Model(&db.RevocationOutbox{}).Where("id = ? AND lease_token = ?", job.ID, lease).Updates(updates).Error; err != nil {
			return err
		}
	}
	return nil
}
