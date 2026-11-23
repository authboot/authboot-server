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

// Package logger is the single logging entry point of the service.
//
// One zap core backs every log line: business logs, the HTTP access log,
// Hertz framework logs (hlog) and the standard library "log" package. All of
// them therefore share the same JSON schema, level switch and output.
//
// Request-scoped fields (request_id, trace_id, ...) travel in the
// context.Context: a middleware binds them once with WithRequestID /
// WithFields, and every downstream From(ctx) or hlog.CtxXxxf(ctx, ...) call
// emits them automatically.
package logger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/cloudwego/hertz/pkg/common/hlog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Supported values of Config.Output.
const (
	OutputFile   = "file"
	OutputStdout = "stdout"
	OutputBoth   = "both"
)

var (
	// level is shared by every logger built in this package, so SetLevel takes
	// effect immediately, including on loggers already bound to a context.
	level = zap.NewAtomicLevelAt(zapcore.InfoLevel)

	global atomic.Pointer[zap.Logger]
)

// Before Init the package logs JSON to stdout at info level, so library code
// and tests never see a nil logger.
func init() {
	global.Store(newLogger(zapcore.Lock(os.Stdout), ""))
}

// Config controls how the global logger is built. The zero value is valid.
type Config struct {
	Service    string // "service" field on every line; defaults to authboot-server
	Level      string // debug/info/warn/error; defaults to info
	Output     string // file, stdout or both; defaults to file
	FilePath   string // rotating log file; defaults to hlog/logs/app.log
	MaxSize    int    // megabytes per file before rotation; defaults to 20
	MaxBackups int    // rotated files to retain; defaults to 5
	MaxAge     int    // days to retain a rotated file; defaults to 10
}

// ConfigFromEnv reads LOG_LEVEL, LOG_OUTPUT and LOG_FILE. Unset variables fall
// back to the Config defaults.
func ConfigFromEnv() Config {
	return Config{
		Level:    os.Getenv("LOG_LEVEL"),
		Output:   os.Getenv("LOG_OUTPUT"),
		FilePath: os.Getenv("LOG_FILE"),
	}
}

func (c Config) withDefaults() Config {
	c.Level = strings.TrimSpace(c.Level)
	c.Output = strings.ToLower(strings.TrimSpace(c.Output))
	c.FilePath = strings.TrimSpace(c.FilePath)
	if c.Service == "" {
		c.Service = "authboot-server"
	}
	if c.Level == "" {
		c.Level = "info"
	}
	if c.Output == "" {
		c.Output = OutputFile
	}
	if c.FilePath == "" {
		c.FilePath = filepath.Join("hlog", "logs", "app.log")
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
	return c
}

// open builds the write target and returns the function that releases it.
func (c Config) open() (zapcore.WriteSyncer, func() error, error) {
	var syncers []zapcore.WriteSyncer
	closeOutput := func() error { return nil }

	if c.Output != OutputStdout {
		// The file name is fixed: lumberjack rotates by size and stamps each
		// backup with its rotation time, so a long-running process never
		// keeps writing into a file named after its start date.
		file := &lumberjack.Logger{
			Filename:   c.FilePath,
			MaxSize:    c.MaxSize,
			MaxBackups: c.MaxBackups,
			MaxAge:     c.MaxAge,
			Compress:   true,
		}
		// An empty write makes lumberjack create the directory and file now,
		// so an unwritable path fails startup instead of dropping logs later.
		if _, err := file.Write(nil); err != nil {
			return nil, nil, errors.Join(fmt.Errorf("logger: open %s: %w", c.FilePath, err), file.Close())
		}
		syncers = append(syncers, zapcore.AddSync(file))
		closeOutput = file.Close
	}
	if c.Output != OutputFile {
		syncers = append(syncers, zapcore.Lock(os.Stdout))
	}
	return zapcore.NewMultiWriteSyncer(syncers...), closeOutput, nil
}

// newLogger builds a JSON logger on ws governed by the package level.
func newLogger(ws zapcore.WriteSyncer, service string) *zap.Logger {
	enc := zap.NewProductionEncoderConfig()
	enc.TimeKey = "ts"
	enc.MessageKey = "message"
	enc.EncodeTime = zapcore.ISO8601TimeEncoder

	l := zap.New(
		zapcore.NewCore(zapcore.NewJSONEncoder(enc), ws, level),
		zap.AddCaller(),
		// Expected failures are logged at error level all the time; a stack
		// on each of them is noise. Keep stacks for panic-class entries.
		zap.AddStacktrace(zapcore.DPanicLevel),
	)
	if service != "" {
		l = l.With(zap.String("service", service))
	}
	return l
}

// Init builds the global logger from cfg, routes hlog and the standard library
// "log" package into it, and returns the cleanup to run at process exit.
//
// Call it once, first thing at startup: hlog.SetLogger is not safe to call
// once requests are being served.
func Init(cfg Config) (cleanup func() error, err error) {
	cfg = cfg.withDefaults()

	lvl, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("logger: invalid level %q: %w", cfg.Level, err)
	}
	switch cfg.Output {
	case OutputFile, OutputStdout, OutputBoth:
	default:
		return nil, fmt.Errorf("logger: invalid output %q (want file, stdout or both)", cfg.Output)
	}
	ws, closeOutput, err := cfg.open()
	if err != nil {
		return nil, err
	}

	level.SetLevel(lvl)
	l := newLogger(ws, cfg.Service)
	global.Store(l)
	hlog.SetLogger(hlogAdapter{})
	restoreStdLog := zap.RedirectStdLog(l.Named("stdlog"))

	return func() error {
		restoreStdLog()
		// Syncing stdout fails on terminals and pipes; the file target is
		// unbuffered, so nothing is lost by ignoring the result.
		_ = l.Sync()
		return closeOutput()
	}, nil
}

// L returns the global logger. Prefer From(ctx) inside a request so the
// request-scoped fields are attached.
func L() *zap.Logger {
	return global.Load()
}

// SetLevel changes the minimum level at runtime (debug/info/warn/error).
func SetLevel(text string) error {
	lvl, err := zapcore.ParseLevel(strings.TrimSpace(text))
	if err != nil {
		return fmt.Errorf("logger: invalid level %q: %w", text, err)
	}
	level.SetLevel(lvl)
	return nil
}
