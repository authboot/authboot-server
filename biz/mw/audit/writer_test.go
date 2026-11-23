package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/pkg/logger"
	"github.com/authboot/authboot-server/pkg/securitymetrics"
)

// strictSchema mirrors tb_admin_audit_logs with the limits MySQL enforces in
// strict mode and SQLite does not: varchar widths (in characters) and JSON
// columns that reject anything but a document.
const strictSchema = `CREATE TABLE tb_admin_audit_logs (
	id              integer PRIMARY KEY AUTOINCREMENT,
	request_id      text CHECK (length(request_id) <= 64),
	trace_id        text CHECK (length(trace_id) <= 64),
	admin_id        integer,
	organization_id integer,
	session_id      text CHECK (length(session_id) <= 64),
	action          text CHECK (length(action) <= 64),
	resource_type   text CHECK (length(resource_type) <= 64),
	resource_id     text CHECK (length(resource_id) <= 128),
	method          text CHECK (length(method) <= 8),
	path            text CHECK (length(path) <= 255),
	ip              text CHECK (length(ip) <= 64),
	user_agent      text CHECK (length(user_agent) <= 255),
	success         numeric,
	status_code     integer,
	err_msg         text CHECK (length(err_msg) <= 512),
	"before"        blob CHECK ("before" IS NULL OR CAST("before" AS text) LIKE '{%'),
	"after"         blob CHECK ("after" IS NULL OR CAST("after" AS text) LIKE '{%'),
	extra           blob CHECK (extra IS NULL OR CAST(extra AS text) LIKE '{%'),
	latency_ms      integer,
	created_at      datetime NOT NULL
)`

type logEntry = map[string]interface{}

// setup points the package at a strict in-memory database and a temporary log
// file. logged closes the logger and returns what was written to it.
func setup(t *testing.T) (logged func() []logEntry) {
	t.Helper()
	conn, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := conn.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1) // one connection, or each would get its own :memory: database
	if err := conn.Exec(strictSchema).Error; err != nil {
		t.Fatal(err)
	}
	oldDB, oldInsert := db.DB, insert
	db.DB = conn
	t.Cleanup(func() {
		db.DB, insert = oldDB, oldInsert
		_ = sqlDB.Close()
	})

	path := filepath.Join(t.TempDir(), "app.log")
	closeLog, err := logger.Init(logger.Config{Output: logger.OutputFile, FilePath: path})
	if err != nil {
		t.Fatal(err)
	}
	return func() []logEntry {
		t.Helper()
		if err := closeLog(); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var out []logEntry
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var e logEntry
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				t.Fatalf("log line is not JSON: %v: %s", err, sc.Text())
			}
			out = append(out, e)
		}
		return out
	}
}

func storedActions(t *testing.T) []string {
	t.Helper()
	var rows []db.AdminAuditLog
	if err := db.DB.Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	actions := make([]string, 0, len(rows))
	for _, r := range rows {
		actions = append(actions, r.Action)
	}
	return actions
}

// failureCount reads audit_write_failure_total the way a scraper does.
func failureCount(t *testing.T) int64 {
	t.Helper()
	token := strings.Repeat("t", 32)
	c := app.NewContext(0)
	c.Request.Header.Set("Authorization", "Bearer "+token)
	securitymetrics.Handler(token)(context.Background(), c)
	const name = "authboot_audit_write_failure_total "
	for _, line := range strings.Split(string(c.Response.Body()), "\n") {
		if strings.HasPrefix(line, name) {
			n, err := strconv.ParseInt(strings.TrimPrefix(line, name), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	}
	t.Fatal("audit_write_failure_total is not exported")
	return 0
}

func entries(actions ...string) []*Entry {
	out := make([]*Entry, 0, len(actions))
	for _, a := range actions {
		out = append(out, &Entry{Action: a, AdminID: 7, Method: "POST", Path: "/x", Success: true})
	}
	return out
}

func sameStrings(got, want []string) bool {
	return strings.Join(got, ",") == strings.Join(want, ",")
}

func TestClamp(t *testing.T) {
	cases := map[string]struct {
		in   string
		max  int
		want string
	}{
		"short":        {"abc", 8, "abc"},
		"exact":        {"abcdefgh", 8, "abcdefgh"},
		"ascii cut":    {"abcdefghij", 8, "abcdefgh"},
		"multibyte":    {strings.Repeat("中", 10), 8, strings.Repeat("中", 8)},
		"mixed":        {"ab中文cd", 3, "ab中"},
		"invalid utf8": {"a\xffb", 8, "a\uFFFDb"},
		"empty":        {"", 8, ""},
	}
	for name, tc := range cases {
		got := clamp(tc.in, tc.max)
		if got != tc.want {
			t.Errorf("%s: clamp(%q, %d) = %q, want %q", name, tc.in, tc.max, got, tc.want)
		}
		if !utf8.ValidString(got) || utf8.RuneCountInString(got) > tc.max {
			t.Errorf("%s: %q is not a valid value of at most %d characters", name, got, tc.max)
		}
	}
}

func TestOversizedRequestFieldsAreStored(t *testing.T) {
	logged := setup(t)
	before := failureCount(t)
	hostile := &Entry{
		RequestID:    strings.Repeat("r", 500),
		TraceID:      strings.Repeat("t", 500),
		SessionID:    strings.Repeat("s", 500),
		ResourceType: strings.Repeat("y", 500),
		ResourceID:   strings.Repeat("i", 500),
		Method:       "PROPPATCHX",
		Path:         "/" + strings.Repeat("p", 2000), // also becomes the action
		IP:           strings.Repeat("1", 500),
		UserAgent:    strings.Repeat("界", 5000) + "\xff",
		ErrMsg:       strings.Repeat("e", 5000),
		Before:       []byte{}, // empty, not absent
	}

	// The premise of this test: the database refuses the row as it arrives.
	raw := &db.AdminAuditLog{UserAgent: hostile.UserAgent, CreatedAt: time.Now()}
	if err := db.InsertAuditLogs([]*db.AdminAuditLog{raw}); err == nil {
		t.Fatal("the strict schema accepted an over-long user agent")
	}

	batch := append(entries("first"), hostile)
	batch = append(batch, entries("last")...)
	writeBatch(batch)

	var rows []db.AdminAuditLog
	if err := db.DB.Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("stored %d rows, want 3", len(rows))
	}
	got := rows[1]
	if n := utf8.RuneCountInString(got.UserAgent); n != maxUserAgentLen || !strings.HasPrefix(got.UserAgent, "界界") {
		t.Errorf("user agent stored with %d characters: %.20q", n, got.UserAgent)
	}
	if len(got.Path) != maxPathLen || len(got.Action) != maxActionLen || len(got.ErrMsg) != maxErrMsgLen {
		t.Errorf("stored lengths path=%d action=%d err_msg=%d", len(got.Path), len(got.Action), len(got.ErrMsg))
	}
	if got.Before != nil {
		t.Errorf("empty before stored as %q, want NULL", got.Before)
	}
	if entries := logged(); len(entries) != 0 {
		t.Errorf("nothing should have reached the fallback log: %v", entries)
	}
	if n := failureCount(t) - before; n != 0 {
		t.Errorf("failure counter moved by %d", n)
	}
}

func TestBadRowDoesNotSinkBatch(t *testing.T) {
	logged := setup(t)
	before := failureCount(t)
	batch := entries("a", "b", "c", "d", "e")
	batch[2].Extra = []byte("not json")
	batch[2].Before = []byte(`{"name":"old"}`)

	writeBatch(batch)

	if got := storedActions(t); !sameStrings(got, []string{"a", "b", "d", "e"}) {
		t.Errorf("stored %v, want every row but c", got)
	}
	if n := failureCount(t) - before; n != 1 {
		t.Errorf("failure counter moved by %d, want 1", n)
	}
	lost := logged()
	if len(lost) != 1 {
		t.Fatalf("fallback log has %d entries, want 1: %v", len(lost), lost)
	}
	e := lost[0]
	if e["logger"] != "audit" || e["message"] != "audit_write_failed" || e["level"] != "error" || e["error"] == "" {
		t.Errorf("unexpected fallback entry: %v", e)
	}
	row, _ := e["row"].(map[string]interface{})
	if row["action"] != "c" || row["admin_id"] != float64(7) || row["method"] != "POST" || row["success"] != true {
		t.Errorf("fallback row lost fields: %v", row)
	}
	// Valid JSON is embedded as JSON, the offending document kept as text.
	if doc, _ := row["before"].(map[string]interface{}); doc["name"] != "old" {
		t.Errorf("before = %v, want the embedded document", row["before"])
	}
	if row["extra"] != "not json" {
		t.Errorf("extra = %v, want the raw text", row["extra"])
	}
	if _, err := time.Parse(time.RFC3339Nano, fmt.Sprint(row["created_at"])); err != nil {
		t.Errorf("created_at is not replayable: %v", row["created_at"])
	}
}

func TestOutageKeepsEveryRowWithoutRetryingThemAll(t *testing.T) {
	logged := setup(t)
	before := failureCount(t)
	calls := 0
	insert = func([]*db.AdminAuditLog) error {
		calls++
		return errors.New("connection refused")
	}
	want := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}

	writeBatch(entries(want...))

	if calls != 1+maxConsecutiveFailures {
		t.Errorf("insert called %d times, want the batch plus %d single rows", calls, maxConsecutiveFailures)
	}
	if n := failureCount(t) - before; n != int64(len(want)) {
		t.Errorf("failure counter moved by %d, want %d", n, len(want))
	}
	var got []string
	for _, e := range logged() {
		row, _ := e["row"].(map[string]interface{})
		got = append(got, fmt.Sprint(row["action"]))
		if e["error"] != "connection refused" {
			t.Errorf("fallback entry does not carry the cause: %v", e)
		}
	}
	if !sameStrings(got, want) {
		t.Errorf("fallback log has %v, want %v", got, want)
	}
}

func TestSingleRowFailureIsNotRetried(t *testing.T) {
	logged := setup(t)
	calls := 0
	insert = func([]*db.AdminAuditLog) error {
		calls++
		return errors.New("boom")
	}

	writeBatch(entries("only"))

	if calls != 1 {
		t.Errorf("insert called %d times, want 1", calls)
	}
	if n := len(logged()); n != 1 {
		t.Errorf("fallback log has %d entries, want 1", n)
	}
}

func TestAsyncWriterStoresEverythingByStop(t *testing.T) {
	logged := setup(t)
	t.Cleanup(func() { queue, stopCh = nil, nil })
	want := make([]string, 0, 250)
	for i := 0; i < 250; i++ {
		want = append(want, fmt.Sprintf("action-%03d", i))
	}

	// A queue far smaller than the load also exercises the synchronous path.
	Init(8)
	Start()
	for _, e := range entries(want...) {
		enqueue(e)
	}
	Stop()

	got := storedActions(t)
	if len(got) != len(want) {
		t.Fatalf("stored %d rows, want %d", len(got), len(want))
	}
	seen := make(map[string]int, len(got))
	for _, a := range got {
		seen[a]++
	}
	for _, a := range want {
		if seen[a] != 1 {
			t.Errorf("%s stored %d times", a, seen[a])
		}
	}
	if lost := logged(); len(lost) != 0 {
		t.Errorf("%d rows fell back to the log", len(lost))
	}
}
