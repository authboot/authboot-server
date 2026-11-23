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

package logger

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/common/hlog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// capture swaps the global logger for one writing into the returned buffer and
// restores every piece of package state when the test ends.
func capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	restoreState(t)
	buf := &bytes.Buffer{}
	global.Store(newLogger(zapcore.AddSync(buf), "test-svc"))
	hlog.SetLogger(hlogAdapter{})
	return buf
}

func restoreState(t *testing.T) {
	t.Helper()
	prevLogger, prevLevel, prevHlog := global.Load(), level.Level(), hlog.DefaultLogger()
	t.Cleanup(func() {
		global.Store(prevLogger)
		level.SetLevel(prevLevel)
		hlog.SetLogger(prevHlog)
	})
}

func decode(t *testing.T, raw []byte) []map[string]interface{} {
	t.Helper()
	var out []map[string]interface{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		var entry map[string]interface{}
		if err := json.Unmarshal(sc.Bytes(), &entry); err != nil {
			t.Fatalf("log line is not JSON: %v: %s", err, sc.Text())
		}
		out = append(out, entry)
	}
	return out
}

func wantField(t *testing.T, entry map[string]interface{}, key string, want interface{}) {
	t.Helper()
	if got := entry[key]; got != want {
		t.Errorf("%s = %v, want %v (entry %v)", key, got, want, entry)
	}
}

// wantCaller asserts the entry was attributed to this test file rather than to
// a wrapper inside the logging stack.
func wantCaller(t *testing.T, entry map[string]interface{}) {
	t.Helper()
	caller, _ := entry["caller"].(string)
	if !strings.Contains(caller, "logger_test.go") {
		t.Errorf("caller = %q, want this test file (entry %v)", caller, entry)
	}
}

func TestContextFieldsReachEveryAPI(t *testing.T) {
	buf := capture(t)
	ctx := WithRequestID(context.Background(), "rid-1")
	ctx = WithFields(ctx, zap.String("trace_id", "trace-1"))

	From(ctx).Info("typed", zap.Int("n", 1))
	CtxWarnw(ctx, "sugared", "k", "v")
	hlog.CtxErrorf(ctx, "boom %d", 7)

	entries := decode(t, buf.Bytes())
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %s", len(entries), buf.String())
	}
	for _, e := range entries {
		wantField(t, e, "service", "test-svc")
		wantField(t, e, "request_id", "rid-1")
		wantField(t, e, "trace_id", "trace-1")
		wantCaller(t, e)
		if _, ok := e["ts"]; !ok {
			t.Errorf("entry has no ts: %v", e)
		}
	}
	wantField(t, entries[0], "message", "typed")
	wantField(t, entries[0], "level", "info")
	wantField(t, entries[1], "message", "sugared")
	wantField(t, entries[1], "level", "warn")
	wantField(t, entries[1], "k", "v")
	wantField(t, entries[2], "message", "boom 7")
	wantField(t, entries[2], "level", "error")

	if got := RequestID(ctx); got != "rid-1" {
		t.Errorf("RequestID = %q, want rid-1", got)
	}
}

func TestContextWithoutFields(t *testing.T) {
	buf := capture(t)

	//nolint:staticcheck // a nil context must not panic
	From(nil).Info("nil ctx")
	CtxInfow(context.Background(), "plain")
	if ctx := WithRequestID(context.Background(), ""); RequestID(ctx) != "" {
		t.Errorf("empty request id was stored")
	}

	entries := decode(t, buf.Bytes())
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %s", len(entries), buf.String())
	}
	for _, e := range entries {
		if _, ok := e["request_id"]; ok {
			t.Errorf("unexpected request_id: %v", e)
		}
	}
}

func TestHlogAdapterFormatting(t *testing.T) {
	buf := capture(t)

	hlog.CtxInfof(context.Background(), "progress 100%")
	hlog.Info("a", "b")
	hlog.SystemLogger().Infof("listening on %s", ":8888")

	entries := decode(t, buf.Bytes())
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %s", len(entries), buf.String())
	}
	wantField(t, entries[0], "message", "progress 100%")
	wantField(t, entries[1], "message", "ab")
	if msg, _ := entries[2]["message"].(string); !strings.HasSuffix(msg, "listening on :8888") {
		t.Errorf("system log message = %q", msg)
	}
	for _, e := range entries {
		wantCaller(t, e)
	}
}

func TestLevelSwitch(t *testing.T) {
	buf := capture(t)
	ctx := context.Background()

	if err := SetLevel("warn"); err != nil {
		t.Fatal(err)
	}
	From(ctx).Info("dropped")
	CtxInfow(ctx, "dropped")
	hlog.CtxInfof(ctx, "dropped")
	hlog.CtxWarnf(ctx, "kept")
	if entries := decode(t, buf.Bytes()); len(entries) != 1 || entries[0]["message"] != "kept" {
		t.Fatalf("at warn level got %s", buf.String())
	}

	// hlog.SetLevel drives the same switch, also for a logger built earlier.
	buf.Reset()
	hlog.SetLevel(hlog.LevelDebug)
	hlog.CtxDebugf(ctx, "debug on")
	if entries := decode(t, buf.Bytes()); len(entries) != 1 || entries[0]["level"] != "debug" {
		t.Fatalf("at debug level got %s", buf.String())
	}

	if err := SetLevel("loud"); err == nil {
		t.Error("SetLevel accepted an unknown level")
	}
}

func TestInitWritesFileAndRedirectsStdLog(t *testing.T) {
	restoreState(t)
	path := filepath.Join(t.TempDir(), "nested", "app.log")

	cleanup, err := Init(Config{Service: "svc", Level: "debug", Output: OutputFile, FilePath: path})
	if err != nil {
		t.Fatal(err)
	}
	L().Debug("from zap")
	hlog.Infof("from %s", "hlog")
	log.Print("from stdlib")
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := decode(t, raw)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %s", len(entries), raw)
	}
	wantField(t, entries[0], "message", "from zap")
	wantField(t, entries[1], "message", "from hlog")
	wantField(t, entries[2], "message", "from stdlib")
	wantField(t, entries[2], "logger", "stdlog")
	for _, e := range entries {
		wantField(t, e, "service", "svc")
		wantCaller(t, e)
	}
}

func TestInitRejectsBadConfig(t *testing.T) {
	restoreState(t)
	before := L()
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]Config{
		"level":  {Level: "loud", Output: OutputStdout},
		"output": {Output: "syslog"},
		// The parent of the log file is a regular file, so it cannot be created.
		"path": {Output: OutputFile, FilePath: filepath.Join(blocker, "app.log")},
	}
	for name, cfg := range cases {
		if _, err := Init(cfg); err == nil {
			t.Errorf("%s: Init accepted %+v", name, cfg)
		}
	}
	if L() != before {
		t.Error("a failed Init replaced the global logger")
	}
}
