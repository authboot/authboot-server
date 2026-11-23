package securitymetrics

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/cloudwego/hertz/pkg/app"
)

// A fixed registry bounds cardinality and deliberately accepts no labels.
var counters = map[string]*atomic.Int64{
	"login_failure_total":        {},
	"mfa_failure_total":          {},
	"stepup_failure_total":       {},
	"revocation_failure_total":   {},
	"worker_failure_total":       {},
	"retention_deleted_total":    {},
	"retention_candidate_total":  {},
	"geoip_unavailable_total":    {},
	"notification_failure_total": {},
	// Audit rows the database refused; each one is in the application log.
	"audit_write_failure_total": {},
}
var Pending atomic.Int64

func Add(name string, n int64) {
	if c := counters[name]; c != nil {
		c.Add(n)
	}
}

func Authorized(c *app.RequestContext, token string) bool {
	header := string(c.GetHeader("Authorization"))
	if !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	provided := strings.TrimPrefix(header, "Bearer ")
	return len(token) >= 32 && subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}

func Handler(token string) app.HandlerFunc {
	return func(_ context.Context, c *app.RequestContext) {
		c.Header("Cache-Control", "no-store")
		if !Authorized(c, token) {
			c.AbortWithStatus(401)
			return
		}
		var b strings.Builder
		for name, v := range counters {
			fmt.Fprintf(&b, "# TYPE authboot_%s counter\nauthboot_%s %d\n", name, name, v.Load())
		}
		fmt.Fprintf(&b, "# TYPE authboot_revocation_pending gauge\nauthboot_revocation_pending %d\n", Pending.Load())
		c.Data(200, "text/plain; version=0.0.4; charset=utf-8", []byte(b.String()))
	}
}
