package accesslog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/middlewares/server/recovery"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"

	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/tracing"
	"github.com/authboot/authboot-server/pkg/logger"
)

type entry = map[string]interface{}

// harness wires the same middleware order as newServer and captures the log
// output of the requests performed through it.
type harness struct {
	t      *testing.T
	engine *route.Engine
	path   string
	done   func() error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.log")
	done, err := logger.Init(logger.Config{Output: logger.OutputFile, FilePath: path})
	if err != nil {
		t.Fatal(err)
	}
	engine := route.NewEngine(config.NewOptions(nil))
	engine.Use(RequestID(), tracing.TraceContext(), New(Skip("/ping", "/ready")), recovery.Recovery())
	return &harness{t: t, engine: engine, path: path, done: done}
}

func (h *harness) get(url string, headers ...ut.Header) *ut.ResponseRecorder {
	return ut.PerformRequest(h.engine, "GET", url, nil, headers...)
}

// entries closes the logger and returns everything it wrote.
func (h *harness) entries() []entry {
	h.t.Helper()
	if err := h.done(); err != nil {
		h.t.Fatal(err)
	}
	raw, err := os.ReadFile(h.path)
	if err != nil {
		h.t.Fatal(err)
	}
	var out []entry
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(nil, 1<<20) // a recovery entry carries a full stack
	for sc.Scan() {
		var e entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			h.t.Fatalf("log line is not JSON: %v: %s", err, sc.Text())
		}
		out = append(out, e)
	}
	return out
}

func wantFields(t *testing.T, got entry, want entry) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v (entry %v)", k, got[k], v, got)
		}
	}
}

func TestHandlerAndAccessLinesShareRequestFields(t *testing.T) {
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	h := newHarness(t)
	h.engine.GET("/users/:id", func(ctx context.Context, c *app.RequestContext) {
		c.Set(jwt.CtxKeyUserID, int64(9))
		c.Set(jwt.CtxKeyOrgID, int64(3))
		hlog.CtxInfof(ctx, "in handler")
		c.String(201, "ok")
	})

	h.get("/users/7?token=secret",
		ut.Header{Key: "X-Request-ID", Value: "rid-42"},
		ut.Header{Key: "traceparent", Value: "00-" + traceID + "-00f067aa0ba902b7-01"},
		ut.Header{Key: "User-Agent", Value: "ua-test"},
	)

	entries := h.entries()
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want handler + access: %v", len(entries), entries)
	}
	for _, e := range entries {
		wantFields(t, e, entry{"request_id": "rid-42", "trace_id": traceID})
	}
	wantFields(t, entries[0], entry{"message": "in handler"})

	access := entries[1]
	wantFields(t, access, entry{
		"logger":     "access",
		"level":      "info",
		"message":    "http_request",
		"method":     "GET",
		"route":      "/users/:id",
		"path":       "/users/7", // no query: it may carry credentials
		"status":     float64(201),
		"user_agent": "ua-test",
		"resp_bytes": float64(2),
		"account_id": float64(9),
		"org_id":     float64(3),
	})
	for _, k := range []string{"latency_ms", "client_ip"} {
		if _, ok := access[k]; !ok {
			t.Errorf("access entry has no %s: %v", k, access)
		}
	}
	if _, ok := access["caller"]; ok {
		t.Errorf("access entry should not carry a caller: %v", access)
	}
}

func TestPanicIsLoggedAsServerError(t *testing.T) {
	h := newHarness(t)
	h.engine.GET("/boom", func(ctx context.Context, c *app.RequestContext) {
		panic("kaboom")
	})

	w := h.get("/boom", ut.Header{Key: "X-Request-ID", Value: "rid-panic"})
	if w.Code != 500 {
		t.Fatalf("status = %d, want 500", w.Code)
	}

	entries := h.entries()
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want recovery + access: %v", len(entries), entries)
	}
	recovered, access := entries[0], entries[1]
	// The panic itself is tied to the request, not only the access line.
	wantFields(t, recovered, entry{"level": "error", "request_id": "rid-panic"})
	if msg, _ := recovered["message"].(string); !strings.Contains(msg, "kaboom") {
		t.Errorf("recovery entry does not report the panic: %v", recovered)
	}
	wantFields(t, access, entry{
		"logger":     "access",
		"level":      "error",
		"route":      "/boom",
		"status":     float64(500),
		"request_id": "rid-panic",
	})
	if _, ok := access["account_id"]; ok {
		t.Errorf("unauthenticated request logged an account: %v", access)
	}
}

func TestSkippedRoutesLogOnlyFailures(t *testing.T) {
	h := newHarness(t)
	h.engine.GET("/ping", func(ctx context.Context, c *app.RequestContext) { c.String(200, "pong") })
	h.engine.GET("/ready", func(ctx context.Context, c *app.RequestContext) { c.AbortWithStatus(503) })

	h.get("/ping")
	h.get("/ready")
	h.get("/missing")

	entries := h.entries()
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want /ready and /missing only: %v", len(entries), entries)
	}
	wantFields(t, entries[0], entry{"route": "/ready", "status": float64(503), "level": "error"})
	// A 4xx is the client's problem and stays at info; no route matched.
	wantFields(t, entries[1], entry{"route": "", "path": "/missing", "status": float64(404), "level": "info"})
}

func TestRequestIDRejectsMalformedInbound(t *testing.T) {
	h := newHarness(t)
	h.engine.GET("/x", func(ctx context.Context, c *app.RequestContext) { c.String(200, "ok") })

	cases := map[string]struct {
		inbound string
		kept    bool
	}{
		"uuid":      {"3f2b6c1e-8d4a-4c59-9a55-0f6f1f0c9f11", true},
		"max len":   {strings.Repeat("a", 64), true},
		"too long":  {strings.Repeat("a", 65), false},
		"spaces":    {"abc def", false},
		"injection": {`x","admin":"true`, false},
	}
	for name, tc := range cases {
		got := h.get("/x", ut.Header{Key: "X-Request-ID", Value: tc.inbound}).Header().Get("X-Request-ID")
		if !validRequestID(got) {
			t.Errorf("%s: response id %q is not well formed", name, got)
		}
		if kept := got == tc.inbound; kept != tc.kept {
			t.Errorf("%s: inbound %q kept = %v, want %v (got %q)", name, tc.inbound, kept, tc.kept, got)
		}
	}
	if got := h.get("/x").Header().Get("X-Request-ID"); !validRequestID(got) {
		t.Errorf("no inbound id: generated %q is not well formed", got)
	}

	// The id on the response is the one written to the log.
	entries := h.entries()
	if len(entries) != len(cases)+1 {
		t.Fatalf("got %d entries, want %d", len(entries), len(cases)+1)
	}
	for _, e := range entries {
		if id, _ := e["request_id"].(string); !validRequestID(id) {
			t.Errorf("logged request_id %q is not well formed", id)
		}
	}
}
