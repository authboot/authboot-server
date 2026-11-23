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

package audit

import (
	"encoding/json"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/pkg/logger"
	"github.com/authboot/authboot-server/pkg/securitymetrics"
)

// Column widths of tb_admin_audit_logs, in characters. Keep in sync with
// db.AdminAuditLog and pkg/configs/sql/init.sql.
const (
	maxIDLen         = 64 // request_id, trace_id, session_id
	maxActionLen     = 64
	maxResourceType  = 64
	maxResourceIDLen = 128
	maxMethodLen     = 8
	maxPathLen       = 255
	maxIPLen         = 64
	maxUserAgentLen  = 255
	maxErrMsgLen     = 512
)

// maxConsecutiveFailures bounds the row-by-row retry after a failed batch.
// One or two bad rows are isolated and the rest of the batch is saved; when
// row after row fails the database itself is the problem, and retrying the
// remaining rows would only stall the writer for one timeout each.
const maxConsecutiveFailures = 3

// insert is swapped out in tests.
var insert = db.InsertAuditLogs

// writeBatch persists entries. It never returns an error: auditing must not
// break the request path. A row the database refuses is written to the
// application log instead (see fallback), so it can still be recovered.
func writeBatch(entries []*Entry) {
	if len(entries) == 0 {
		return
	}
	now := time.Now()
	rows := make([]*db.AdminAuditLog, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, toRow(e, now))
	}

	err := insert(rows)
	if err == nil {
		return
	}
	if len(rows) == 1 {
		fallback(rows[0], err)
		return
	}
	// A multi-row INSERT fails as a whole, so one bad row would take the
	// other rows of the batch down with it. Retry them one at a time. If the
	// first attempt failed after the server had applied it, this duplicates
	// rows, which an audit trail tolerates better than losing them.
	consecutive := 0
	for _, row := range rows {
		if consecutive >= maxConsecutiveFailures {
			fallback(row, err)
			continue
		}
		if rowErr := insert([]*db.AdminAuditLog{row}); rowErr != nil {
			consecutive++
			err = rowErr
			fallback(row, rowErr)
			continue
		}
		consecutive = 0
	}
}

// toRow converts an entry into the row to insert. Request-derived strings
// (User-Agent, path, ...) are attacker-controlled: an over-long or malformed
// one must not make the database reject the row.
func toRow(e *Entry, now time.Time) *db.AdminAuditLog {
	action := e.Action
	if action == "" {
		action = e.Method + " " + e.Path
	}
	return &db.AdminAuditLog{
		RequestID:      clamp(e.RequestID, maxIDLen),
		TraceID:        clamp(e.TraceID, maxIDLen),
		AdminID:        e.AdminID,
		OrganizationID: e.OrganizationID,
		SessionID:      clamp(e.SessionID, maxIDLen),
		Action:         clamp(action, maxActionLen),
		ResourceType:   clamp(e.ResourceType, maxResourceType),
		ResourceID:     clamp(e.ResourceID, maxResourceIDLen),
		Method:         clamp(e.Method, maxMethodLen),
		Path:           clamp(e.Path, maxPathLen),
		IP:             clamp(e.IP, maxIPLen),
		UserAgent:      clamp(e.UserAgent, maxUserAgentLen),
		Success:        e.Success,
		StatusCode:     e.StatusCode,
		ErrMsg:         clamp(e.ErrMsg, maxErrMsgLen),
		Before:         jsonOrNull(e.Before),
		After:          jsonOrNull(e.After),
		Extra:          jsonOrNull(e.Extra),
		LatencyMs:      e.LatencyMs,
		CreatedAt:      now,
	}
}

// clamp makes s safe for a utf8mb4 varchar(max) column: invalid UTF-8 is
// replaced and the result is cut to max characters, never inside a character.
func clamp(s string, max int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= max {
		return s
	}
	n := 0
	for i := range s {
		if n == max {
			return s[:i]
		}
		n++
	}
	return s
}

// jsonOrNull stores an empty document as NULL: a JSON column rejects "".
func jsonOrNull(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// fallback records a row the database refused. The full row goes to the
// application log under the logger name "audit" as message "audit_write_failed",
// from where it can be replayed; audit_write_failure_total counts such rows.
func fallback(row *db.AdminAuditLog, cause error) {
	securitymetrics.Add("audit_write_failure_total", 1)
	logger.L().Named("audit").WithOptions(zap.WithCaller(false)).Error("audit_write_failed",
		zap.Error(cause),
		zap.Object("row", rowObject{row}),
	)
}

// rowObject logs a row with its column names. The JSON columns are embedded as
// JSON rather than base64, which is what encoding/json does to a []byte.
type rowObject struct{ *db.AdminAuditLog }

func (r rowObject) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("request_id", r.RequestID)
	enc.AddString("trace_id", r.TraceID)
	enc.AddInt64("admin_id", r.AdminID)
	enc.AddInt64("organization_id", r.OrganizationID)
	enc.AddString("session_id", r.SessionID)
	enc.AddString("action", r.Action)
	enc.AddString("resource_type", r.ResourceType)
	enc.AddString("resource_id", r.ResourceID)
	enc.AddString("method", r.Method)
	enc.AddString("path", r.Path)
	enc.AddString("ip", r.IP)
	enc.AddString("user_agent", r.UserAgent)
	enc.AddBool("success", r.Success)
	enc.AddInt32("status_code", r.StatusCode)
	enc.AddString("err_msg", r.ErrMsg)
	addJSON(enc, "before", r.Before)
	addJSON(enc, "after", r.After)
	addJSON(enc, "extra", r.Extra)
	enc.AddInt64("latency_ms", r.LatencyMs)
	enc.AddString("created_at", r.CreatedAt.Format(time.RFC3339Nano))
	return nil
}

func addJSON(enc zapcore.ObjectEncoder, key string, raw []byte) {
	if len(raw) == 0 {
		return
	}
	// Invalid JSON is the likely reason the row was refused; keep it as text.
	if !json.Valid(raw) || enc.AddReflected(key, json.RawMessage(raw)) != nil {
		enc.AddString(key, string(raw))
	}
}
