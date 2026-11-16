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

// Package tracing propagates the W3C Trace Context trace-id so other layers
// (e.g. the audit middleware) can tag records with it. It is intentionally
// lightweight: it only READS the inbound `traceparent` header — it emits no
// spans and needs no exporter or startup wiring, so it adds zero runtime cost
// and does not touch existing logic. It is OTel-compatible: a real OTel tracer
// upstream sets the very same header, so this keeps working once/if one is added.
package tracing

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

// CtxKeyTraceID is the request-context key under which the extracted trace-id
// is stored. Empty/absent when the request carries no (valid) trace context.
const CtxKeyTraceID = "trace_id"

// zeroTraceID is the all-zero trace-id, which the W3C spec defines as invalid.
const zeroTraceID = "00000000000000000000000000000000"

// TraceContext extracts the trace-id from the inbound `traceparent` header and
// puts it in the request context. If the header is missing or malformed, it
// sets nothing (trace_id stays empty). Mount it early, e.g. alongside requestid.
func TraceContext() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		if tid := traceIDFromHeader(string(c.GetHeader("traceparent"))); tid != "" {
			c.Set(CtxKeyTraceID, tid)
		}
		c.Next(ctx)
	}
}

// traceIDFromHeader parses a W3C traceparent header and returns its 32-hex
// trace-id, or "" when absent/invalid. Format:
//
//	version "-" trace-id(32hex) "-" parent-id(16hex) "-" flags(2hex)
//	e.g. 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
func traceIDFromHeader(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	parts := strings.Split(h, "-")
	if len(parts) < 4 {
		return ""
	}
	tid := parts[1]
	if len(tid) != 32 || tid == zeroTraceID {
		return ""
	}
	if _, err := hex.DecodeString(tid); err != nil {
		return ""
	}
	return tid
}
