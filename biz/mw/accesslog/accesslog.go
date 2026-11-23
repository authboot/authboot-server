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

// Package accesslog emits one structured log line per HTTP request and binds
// the request-scoped ids to the context, so every log written while handling
// the request can be correlated with its access line.
//
// Mount order matters:
//
//	h.Use(
//		accesslog.RequestID(),  // 1. settle the request id
//		tracing.TraceContext(), // 2. extract the trace id
//		accesslog.New(),        // 3. bind both, log when the request ends
//		recovery.Recovery(),    // 4. inside New, so a panic is logged as a 500
//		...
//	)
package accesslog

import (
	"context"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/hertz-contrib/requestid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/tracing"
	"github.com/authboot/authboot-server/pkg/clientip"
	"github.com/authboot/authboot-server/pkg/logger"
)

const (
	requestIDHeader = "X-Request-ID"
	maxRequestIDLen = 64
)

// RequestID wraps hertz-contrib/requestid and refuses to adopt a malformed
// inbound X-Request-ID: the id ends up in every log line and audit row, so a
// caller must not be able to inject arbitrary or oversized text there. An id
// is accepted when it is 1-64 characters of [A-Za-z0-9_-] (a UUID qualifies);
// anything else is dropped and a fresh one is generated.
func RequestID() app.HandlerFunc {
	next := requestid.New()
	return func(ctx context.Context, c *app.RequestContext) {
		if id := c.Request.Header.Get(requestIDHeader); id != "" && !validRequestID(id) {
			c.Request.Header.Del(requestIDHeader)
		}
		next(ctx, c)
	}
}

func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '-', ch == '_':
		default:
			return false
		}
	}
	return true
}

type options struct {
	skip map[string]struct{}
}

// Option configures New.
type Option func(*options)

// Skip silences successful requests to the given route patterns (as
// registered, e.g. "/ping"), which keeps health checks and metric scrapes
// from drowning out real traffic. Responses with status >= 400 on those
// routes are still logged.
func Skip(routes ...string) Option {
	return func(o *options) {
		for _, r := range routes {
			o.skip[r] = struct{}{}
		}
	}
}

// New returns the access log middleware.
//
// Before the handlers run it binds request_id and trace_id to the context
// passed down the chain, so logger.From(ctx) and hlog.CtxXxxf(ctx, ...) carry
// them. After the handlers return it writes one "http_request" line under the
// logger name "access": error level for 5xx, info otherwise.
func New(opts ...Option) app.HandlerFunc {
	o := options{skip: map[string]struct{}{}}
	for _, opt := range opts {
		opt(&o)
	}

	return func(ctx context.Context, c *app.RequestContext) {
		start := time.Now()
		ctx = logger.WithRequestID(ctx, requestid.Get(c))
		if traceID := c.GetString(tracing.CtxKeyTraceID); traceID != "" {
			ctx = logger.WithFields(ctx, zap.String("trace_id", traceID))
		}

		c.Next(ctx)

		status := c.Response.StatusCode()
		route := c.FullPath()
		if _, skipped := o.skip[route]; skipped && status < 400 {
			return
		}
		lvl := zapcore.InfoLevel
		if status >= 500 {
			lvl = zapcore.ErrorLevel
		}
		ce := logger.From(ctx).Named("access").WithOptions(zap.WithCaller(false)).Check(lvl, "http_request")
		if ce == nil {
			return
		}

		fields := []zap.Field{
			zap.String("method", string(c.Request.Header.Method())),
			// route is the registered pattern ("" when nothing matched): the
			// low-cardinality key to aggregate on. path is the concrete URL
			// without its query, which may carry credentials.
			zap.String("route", route),
			zap.String("path", string(c.Request.URI().PathOriginal())),
			zap.Int("status", status),
			zap.Int64("latency_ms", time.Since(start).Milliseconds()),
			zap.String("client_ip", clientip.FromContext(c)),
			zap.String("user_agent", string(c.UserAgent())),
		}
		if n, ok := responseSize(c); ok {
			fields = append(fields, zap.Int("resp_bytes", n))
		}
		// Set by the session guards further down the chain. On admin routes
		// the account is the admin, on user routes the end user.
		if id := c.GetInt64(jwt.CtxKeyUserID); id != 0 {
			fields = append(fields, zap.Int64("account_id", id))
		}
		if id := c.GetInt64(jwt.CtxKeyOrgID); id != 0 {
			fields = append(fields, zap.Int64("org_id", id))
		}
		ce.Write(fields...)
	}
}

// responseSize reports the body size without consuming it. A streamed body of
// unknown length (chunked) has no size yet when the handlers return.
func responseSize(c *app.RequestContext) (int, bool) {
	if !c.Response.IsBodyStream() {
		return len(c.Response.BodyBytes()), true
	}
	if n := c.Response.Header.ContentLength(); n >= 0 {
		return n, true
	}
	return 0, false
}
