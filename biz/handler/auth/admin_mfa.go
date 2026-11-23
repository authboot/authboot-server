package auth

import (
	"context"

	service "github.com/authboot/authboot-server/biz/service/auth"
	"github.com/authboot/authboot-server/pkg/securitymetrics"
	"github.com/cloudwego/hertz/pkg/app"
)

// Security endpoints intentionally return generic failures, never SQL errors,
// submitted credentials, encrypted secrets or recovery-code hashes.
func AdminMFA(action string) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.Header("Cache-Control", "no-store")
		var req service.MFARequest
		if err := c.BindAndValidate(&req); err != nil {
			c.JSON(400, map[string]any{"message": "invalid request"})
			return
		}
		s := service.NewAdminAuthService(ctx, c)
		var out any
		var err error
		switch action {
		case "verify":
			out, err = s.VerifyAdminMFA(&req)
		case "step-up":
			out, err = s.AdminStepUp(&req)
		default:
			out, err = s.AdminMFAAction(action, &req)
		}
		if err != nil {
			if action == "step-up" {
				securitymetrics.Add("stepup_failure_total", 1)
			} else {
				securitymetrics.Add("mfa_failure_total", 1)
			}
			c.JSON(403, map[string]any{"message": "security verification failed"})
			return
		}
		c.JSON(200, out)
	}
}
