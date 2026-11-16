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

// Package logger is the project's structured logging foundation built on zap.
// It centralizes logger construction (JSON encoding, level control, file
// rotation) and offers context-aware helpers that automatically attach the
// request id carried in the request context.
package logger

import (
	"context"
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// ctxKey is a private type for context keys defined in this package, avoiding
// collisions with keys from other packages.
type ctxKey struct{}

// requestIDKey is the context key under which the per-request id is stored.
var requestIDKey = ctxKey{}

var (
	base  *zap.Logger
	sugar *zap.SugaredLogger
	once  sync.Once
)

// Config controls how the global logger is built. The zero value is valid and
// yields an info-level, stdout-only JSON logger.
type Config struct {
	Level      string // debug/info/warn/error; defaults to info
	FilePath   string // rotating log file path; empty means file output disabled
	MaxSize    int    // megabytes per file before rotation; defaults to 20
	MaxBackups int    // number of rotated files to retain; defaults to 5
	MaxAge     int    // days to retain a rotated file; defaults to 10
	Compress   bool   // gzip-compress rotated files
	Console    bool   // also write to stdout (always on when FilePath is empty)
}

// withDefaults fills unset fields with sensible production defaults.
func (c *Config) withDefaults() {
	if c.Level == "" {
		c.Level = "info"
	}
	if c.MaxSize == 0 {
		c.MaxSize = 20
	}
	if c.MaxBackups == 0 {
		c.MaxBackups = 5
	}
	if c.MaxAge == 0 {
		c.MaxAge = 10
	}
	if c.FilePath == "" {
		c.Console = true
	}
}

// parseLevel maps a textual level to its zapcore equivalent, falling back to
// info level for unknown values.
func parseLevel(level string) zapcore.Level {
	lv, err := zapcore.ParseLevel(level)
	if err != nil {
		return zapcore.InfoLevel
	}
	return lv
}

// Init builds the global logger from cfg. It is safe to call multiple times;
// only the first call takes effect, so startup code can initialize it once.
func Init(cfg Config) {
	once.Do(func() {
		build(cfg)
	})
}

// build constructs the zap logger and its sugared companion from cfg.
func build(cfg Config) {
	cfg.withDefaults()

	encCfg := zap.NewProductionEncoderConfig()
	encCfg.MessageKey = "message"
	encCfg.TimeKey = "ts"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder := zapcore.NewJSONEncoder(encCfg)
	level := zap.NewAtomicLevelAt(parseLevel(cfg.Level))

	cores := make([]zapcore.Core, 0, 2)
	if cfg.FilePath != "" {
		ws := zapcore.AddSync(&lumberjack.Logger{
			Filename:   cfg.FilePath,
			MaxSize:    cfg.MaxSize,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAge,
			Compress:   cfg.Compress,
		})
		cores = append(cores, zapcore.NewCore(encoder, ws, level))
	}
	if cfg.Console {
		cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), level))
	}

	base = zap.New(zapcore.NewTee(cores...), zap.AddCaller(), zap.AddCallerSkip(1))
	sugar = base.Sugar()
}

// L returns the global sugared logger, initializing it with defaults on first
// use so callers never receive a nil logger.
func L() *zap.SugaredLogger {
	if sugar == nil {
		Init(Config{})
	}
	return sugar
}

// Sync flushes any buffered log entries; call it before the process exits.
func Sync() error {
	if base == nil {
		return nil
	}
	return base.Sync()
}

// WithRequestID returns a child context carrying the given request id so that
// downstream Ctx* logging calls can attach it automatically.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID extracts the request id previously stored by WithRequestID,
// returning an empty string when absent.
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// ctxFields prepends the request id (when present) to the caller-supplied
// key/value pairs.
func ctxFields(ctx context.Context, kv []interface{}) []interface{} {
	if id := RequestID(ctx); id != "" {
		return append([]interface{}{"request_id", id}, kv...)
	}
	return kv
}

// CtxDebugw logs a debug message with structured fields and the context request id.
func CtxDebugw(ctx context.Context, msg string, kv ...interface{}) {
	L().Debugw(msg, ctxFields(ctx, kv)...)
}

// CtxInfow logs an info message with structured fields and the context request id.
func CtxInfow(ctx context.Context, msg string, kv ...interface{}) {
	L().Infow(msg, ctxFields(ctx, kv)...)
}

// CtxWarnw logs a warning message with structured fields and the context request id.
func CtxWarnw(ctx context.Context, msg string, kv ...interface{}) {
	L().Warnw(msg, ctxFields(ctx, kv)...)
}

// CtxErrorw logs an error message with structured fields and the context request id.
func CtxErrorw(ctx context.Context, msg string, kv ...interface{}) {
	L().Errorw(msg, ctxFields(ctx, kv)...)
}
