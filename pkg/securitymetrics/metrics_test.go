package securitymetrics

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
)

func TestMetricsAuthentication(t *testing.T) {
	token := strings.Repeat("t", 32)
	for _, tc := range []struct {
		configured, provided string
		status               int
	}{{"", "", 401}, {token, "", 401}, {token, "wrong", 401}, {token, token, 200}} {
		c := app.NewContext(0)
		c.Request.Header.Set("Authorization", "Bearer "+tc.provided)
		Handler(tc.configured)(context.Background(), c)
		if c.Response.StatusCode() != tc.status {
			t.Fatal("metrics auth", c.Response.StatusCode())
		}
		if tc.status == 200 {
			body := string(c.Response.Body())
			if !strings.Contains(body, "authboot_revocation_pending") || strings.Contains(body, token) {
				t.Fatal("invalid exposition")
			}
		}
	}
}
