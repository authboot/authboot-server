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

// Package httpclient provides a drop-in *http.Client whose transport uniformly
// logs every downstream call (method, host, path, status, latency) via the
// project logger and propagates the request id to the downstream service.
package httpclient

import (
	"net/http"
	"time"

	"github.com/authboot/authboot-server/pkg/logger"
)

// requestIDHeader is the HTTP header used to forward the request id downstream.
const requestIDHeader = "X-Request-ID"

// options holds the tunable settings applied by New.
type options struct {
	timeout   time.Duration
	transport http.RoundTripper
}

// Option configures the client built by New.
type Option func(*options)

// WithTimeout overrides the default per-request timeout (10s).
func WithTimeout(d time.Duration) Option {
	return func(o *options) { o.timeout = d }
}

// WithTransport sets the underlying RoundTripper that actually performs the
// request; useful for custom TLS, proxies or testing. Defaults to
// http.DefaultTransport.
func WithTransport(rt http.RoundTripper) Option {
	return func(o *options) { o.transport = rt }
}

// New returns an *http.Client that logs every downstream call and forwards the
// request id. It is safe to share across goroutines and reuse for all outbound
// HTTP traffic.
func New(opts ...Option) *http.Client {
	o := options{
		timeout:   10 * time.Second,
		transport: http.DefaultTransport,
	}
	for _, opt := range opts {
		opt(&o)
	}
	if o.transport == nil {
		o.transport = http.DefaultTransport
	}
	return &http.Client{
		Timeout:   o.timeout,
		Transport: &loggingTransport{base: o.transport},
	}
}

// loggingTransport wraps a RoundTripper to emit a structured log entry per call
// and to carry the request id into the outbound request headers.
type loggingTransport struct {
	base http.RoundTripper
}

// RoundTrip executes the request through the wrapped transport while recording
// its outcome. It clones the request before mutating headers to honor the
// http.RoundTripper contract, and logs only host and path (never the raw query)
// to avoid leaking credentials carried as query parameters.
func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	// Forward the request id downstream without mutating the caller's request.
	if rid := logger.RequestID(ctx); rid != "" && req.Header.Get(requestIDHeader) == "" {
		req = req.Clone(ctx)
		req.Header.Set(requestIDHeader, rid)
	}

	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	latencyMs := time.Since(start).Milliseconds()

	host := req.URL.Host
	path := req.URL.Path
	if err != nil {
		logger.CtxErrorw(ctx, "downstream_call",
			"method", req.Method,
			"host", host,
			"path", path,
			"latency_ms", latencyMs,
			"error", err.Error(),
		)
		return resp, err
	}

	logger.CtxInfow(ctx, "downstream_call",
		"method", req.Method,
		"host", host,
		"path", path,
		"status", resp.StatusCode,
		"latency_ms", latencyMs,
	)
	return resp, nil
}
