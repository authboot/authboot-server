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

// Package audit records an append-only trail of internal admin actions. The
// Middleware captures the request envelope automatically (who/when/where/
// outcome); services enrich a row with semantic detail via Annotate (resource,
// before/after) or log one-shot events (login/logout) via Record. Rows are
// written asynchronously in batches; if the queue is full it falls back to a
// synchronous write so a security event is never dropped.
package audit

import (
	"context"
	"sync"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"github.com/hertz-contrib/requestid"

	"github.com/authboot/authboot-server/biz/dal/db"
)

// ctxEntryKey holds the in-flight *Entry that Middleware creates and Annotate enriches.
const ctxEntryKey = "audit_entry"

// Entry is a single audit record in flight. Before/After/Extra are raw JSON the
// service supplies ALREADY REDACTED (never put passwords, tokens, or secrets here).
type Entry struct {
	RequestID      string
	TraceID        string
	AdminID        int64
	OrganizationID int64
	SessionID      string
	Action         string
	ResourceType   string
	ResourceID     string
	Method         string
	Path           string
	IP             string
	UserAgent      string
	Success        bool
	StatusCode     int32
	ErrMsg         string
	Before         []byte
	After          []byte
	Extra          []byte
	LatencyMs      int64
}

var (
	queue         chan *Entry
	stopCh        chan struct{}
	wg            sync.WaitGroup
	batchSize     = 100
	flushInterval = 2 * time.Second
)

// Init sizes the async queue. Call once before Start (e.g. audit.Init(4096)).
func Init(bufferSize int) {
	queue = make(chan *Entry, bufferSize)
	stopCh = make(chan struct{})
}

// Start launches the background batch writer. Safe to skip: without it, entries
// are written synchronously (see enqueue).
func Start() {
	if queue == nil {
		Init(4096)
	}
	wg.Add(1)
	go worker()
}

// Stop drains the queue, flushes, and waits for the writer to exit. Call on
// graceful shutdown.
func Stop() {
	if stopCh != nil {
		close(stopCh)
	}
	wg.Wait()
}

// PLACEHOLDER_AUDIT

// Middleware records every request it wraps. Mount it on admin routes AFTER the
// auth guard (so AdminID/OrganizationID/SessionID are set) — typically right
// after AdminSessionAuth. It fills the envelope automatically; services
// add resource/diff detail via Annotate during the handler.
func Middleware() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		start := time.Now()
		e := &Entry{
			RequestID:      requestid.Get(c),
			TraceID:        ctxString(c, "trace_id"),
			AdminID:        ctxInt64(c, "current_user_id"),
			OrganizationID: ctxInt64(c, "organization_id"),
			SessionID:      ctxString(c, "session_id"),
			Method:         string(c.Method()),
			Path:           string(c.Path()),
			IP:             c.ClientIP(),
			UserAgent:      string(c.UserAgent()),
		}
		c.Set(ctxEntryKey, e)

		c.Next(ctx)

		e.LatencyMs = time.Since(start).Milliseconds()
		// Default outcome from HTTP status; a handler/service that knows the
		// business result should override via Annotate (StatusCode/ErrMsg/Success).
		if e.StatusCode == 0 && e.ErrMsg == "" {
			e.Success = c.Response.StatusCode() < 400
		}
		enqueue(e)
	}
}

// Annotate enriches the in-flight entry created by Middleware. No-op if the
// route is not wrapped by Middleware.
func Annotate(c *app.RequestContext, fn func(*Entry)) {
	v, ok := c.Get(ctxEntryKey)
	if !ok {
		return
	}
	if e, ok := v.(*Entry); ok {
		fn(e)
	}
}

// Record logs a one-shot event for a route NOT wrapped by Middleware — e.g.
// AdminLogin, where the admin id is only known after credentials verify and the
// route runs before the auth guard. The caller sets the semantic fields
// (Action, AdminID, Success, ...); Record fills the request envelope from c.
func Record(c *app.RequestContext, e *Entry) {
	if e == nil {
		return
	}
	if e.RequestID == "" {
		e.RequestID = requestid.Get(c)
	}
	if e.TraceID == "" {
		e.TraceID = ctxString(c, "trace_id")
	}
	if e.Method == "" {
		e.Method = string(c.Method())
	}
	if e.Path == "" {
		e.Path = string(c.Path())
	}
	if e.IP == "" {
		e.IP = c.ClientIP()
	}
	if e.UserAgent == "" {
		e.UserAgent = string(c.UserAgent())
	}
	enqueue(e)
}

// enqueue hands an entry to the async writer; if the queue is full (or the
// writer was never started) it writes synchronously so audit rows are not lost.
func enqueue(e *Entry) {
	if queue == nil {
		writeBatch([]*Entry{e})
		return
	}
	select {
	case queue <- e:
	default:
		writeBatch([]*Entry{e})
	}
}

func worker() {
	defer wg.Done()
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	batch := make([]*Entry, 0, batchSize)
	flush := func() {
		if len(batch) > 0 {
			writeBatch(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case e := <-queue:
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-stopCh:
			for {
				select {
				case e := <-queue:
					batch = append(batch, e)
				default:
					flush()
					return
				}
			}
		}
	}
}

// writeBatch persists entries. A DB error is logged, not returned: auditing
// must never break the request path.
func writeBatch(entries []*Entry) {
	if len(entries) == 0 {
		return
	}
	now := time.Now()
	rows := make([]*db.AdminAuditLog, 0, len(entries))
	for _, e := range entries {
		action := e.Action
		if action == "" {
			action = e.Method + " " + e.Path
		}
		rows = append(rows, &db.AdminAuditLog{
			RequestID:      e.RequestID,
			TraceID:        e.TraceID,
			AdminID:        e.AdminID,
			OrganizationID: e.OrganizationID,
			SessionID:      e.SessionID,
			Action:         action,
			ResourceType:   e.ResourceType,
			ResourceID:     e.ResourceID,
			Method:         e.Method,
			Path:           e.Path,
			IP:             e.IP,
			UserAgent:      e.UserAgent,
			Success:        e.Success,
			StatusCode:     e.StatusCode,
			ErrMsg:         e.ErrMsg,
			Before:         e.Before,
			After:          e.After,
			Extra:          e.Extra,
			LatencyMs:      e.LatencyMs,
			CreatedAt:      now,
		})
	}
	if err := db.InsertAuditLogs(rows); err != nil {
		hlog.Errorf("audit: failed to write %d log(s): %v", len(rows), err)
	}
}

func ctxInt64(c *app.RequestContext, key string) int64 {
	if v, ok := c.Get(key); ok {
		if id, ok := v.(int64); ok {
			return id
		}
	}
	return 0
}

func ctxString(c *app.RequestContext, key string) string {
	if v, ok := c.Get(key); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
