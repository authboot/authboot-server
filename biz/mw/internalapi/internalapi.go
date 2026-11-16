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

// Package internal authenticates service-to-service (internal) API calls.
// Unlike the user/admin JWT flows, internal routes are guarded by a single
// shared API token carried in the X-Internal-Token header. It is meant for the
// platform's own services (Admin backend, worker processes, other
// microservices) and must NOT be exposed to end users.
package internal

import (
	"context"
	"crypto/subtle"
	"fmt"
	"os"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol/consts"

	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/authboot/authboot-server/pkg/utils"
)

// CtxKey marks a request that has passed Auth().
const CtxKey = "internal_auth_ctx"

// HeaderName is the request header carrying the internal API token.
const HeaderName = "X-Internal-Token"

// token returns the internal API token from the environment. Fails closed
// (os.Exit) when unset, so internal routes are never accidentally exposed
// without an explicit secret — mirroring the jwt package's env-key handling.
func token() string {
	t := os.Getenv("INTERNAL_API_TOKEN")
	if t == "" {
		fmt.Fprintf(os.Stderr, "fatal: INTERNAL_API_TOKEN is not set. Generate one with: openssl rand -base64 32\n")
		os.Exit(1)
	}
	return t
}

// Auth returns middleware that requires the X-Internal-Token header to match
// the INTERNAL_API_TOKEN env value. Comparison is constant-time to avoid
// timing side channels. Mount it on the /api/v1/internal/... route group.
func Auth() app.HandlerFunc {
	expected := token()
	return func(ctx context.Context, c *app.RequestContext) {
		got := c.GetHeader(HeaderName)
		if subtle.ConstantTimeCompare(got, []byte(expected)) != 1 {
			c.JSON(consts.StatusUnauthorized, utils.BuildBaseResp(errno.AuthorizationFailedErr))
			c.Abort()
			return
		}
		c.Set(CtxKey, true)
		c.Next(ctx)
	}
}

// IsAuthenticated reports whether the request passed Auth(). Useful for
// handler-level guards where a group-level middleware is not enough.
func IsAuthenticated(c *app.RequestContext) bool {
	v, ok := c.Get(CtxKey)
	return ok && v == true
}
