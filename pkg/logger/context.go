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
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type (
	loggerKey    struct{}
	requestIDKey struct{}
)

// WithFields returns a child context whose logger carries fields in addition
// to the ones already bound to ctx.
func WithFields(ctx context.Context, fields ...zap.Field) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(fields) == 0 {
		return ctx
	}
	return context.WithValue(ctx, loggerKey{}, From(ctx).With(fields...))
}

// From returns the logger bound to ctx, or the global logger when none is.
func From(ctx context.Context) *zap.Logger {
	if ctx != nil {
		if l, ok := ctx.Value(loggerKey{}).(*zap.Logger); ok {
			return l
		}
	}
	return L()
}

// WithRequestID binds the request id to ctx: it becomes the request_id field
// of every log line and is readable through RequestID for propagation to
// downstream services. An empty id leaves ctx unchanged.
func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, requestIDKey{}, id)
	return WithFields(ctx, zap.String("request_id", id))
}

// RequestID returns the id stored by WithRequestID, or "" when absent.
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// CtxDebugw logs msg at debug level with alternating key/value pairs and the
// fields bound to ctx.
func CtxDebugw(ctx context.Context, msg string, kv ...interface{}) {
	logw(ctx, zapcore.DebugLevel, msg, kv)
}

// CtxInfow is CtxDebugw at info level.
func CtxInfow(ctx context.Context, msg string, kv ...interface{}) {
	logw(ctx, zapcore.InfoLevel, msg, kv)
}

// CtxWarnw is CtxDebugw at warn level.
func CtxWarnw(ctx context.Context, msg string, kv ...interface{}) {
	logw(ctx, zapcore.WarnLevel, msg, kv)
}

// CtxErrorw is CtxDebugw at error level.
func CtxErrorw(ctx context.Context, msg string, kv ...interface{}) {
	logw(ctx, zapcore.ErrorLevel, msg, kv)
}

func logw(ctx context.Context, lvl zapcore.Level, msg string, kv []interface{}) {
	l := From(ctx)
	if !l.Core().Enabled(lvl) {
		return
	}
	// Skip logw and the exported CtxXxxw wrapper so "caller" is the call site.
	s := l.WithOptions(zap.AddCallerSkip(2)).Sugar()
	switch lvl {
	case zapcore.DebugLevel:
		s.Debugw(msg, kv...)
	case zapcore.InfoLevel:
		s.Infow(msg, kv...)
	case zapcore.WarnLevel:
		s.Warnw(msg, kv...)
	default:
		s.Errorw(msg, kv...)
	}
}
