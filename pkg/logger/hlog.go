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
	"fmt"
	"io"

	"github.com/cloudwego/hertz/pkg/common/hlog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// hlogAdapter routes Hertz's hlog into this package, so framework logs and
// existing hlog.CtxXxxf call sites share the global core and pick up the
// fields bound to their context.
type hlogAdapter struct{}

var _ hlog.FullLogger = hlogAdapter{}

// hlogCallerSkip is the number of frames between the zap call in write and
// the code that logged: write, the adapter method, and the hlog package
// function (or Hertz's system logger wrapper).
const hlogCallerSkip = 3

func write(l *zap.Logger, lvl zapcore.Level, format string, v []interface{}) {
	if !l.Core().Enabled(lvl) {
		return
	}
	msg := format
	if len(v) > 0 {
		if format == "" {
			msg = fmt.Sprint(v...)
		} else {
			msg = fmt.Sprintf(format, v...)
		}
	}
	// With no arguments the format is emitted verbatim, so a caller passing
	// arbitrary text as the format cannot produce "%!x(MISSING)" garbage.
	if ce := l.WithOptions(zap.AddCallerSkip(hlogCallerSkip)).Check(lvl, msg); ce != nil {
		ce.Write()
	}
}

// hlog has two levels zap lacks: Trace is logged as debug, Notice as info.

func (hlogAdapter) Trace(v ...interface{})  { write(L(), zapcore.DebugLevel, "", v) }
func (hlogAdapter) Debug(v ...interface{})  { write(L(), zapcore.DebugLevel, "", v) }
func (hlogAdapter) Info(v ...interface{})   { write(L(), zapcore.InfoLevel, "", v) }
func (hlogAdapter) Notice(v ...interface{}) { write(L(), zapcore.InfoLevel, "", v) }
func (hlogAdapter) Warn(v ...interface{})   { write(L(), zapcore.WarnLevel, "", v) }
func (hlogAdapter) Error(v ...interface{})  { write(L(), zapcore.ErrorLevel, "", v) }
func (hlogAdapter) Fatal(v ...interface{})  { write(L(), zapcore.FatalLevel, "", v) }

func (hlogAdapter) Tracef(format string, v ...interface{}) {
	write(L(), zapcore.DebugLevel, format, v)
}

func (hlogAdapter) Debugf(format string, v ...interface{}) {
	write(L(), zapcore.DebugLevel, format, v)
}

func (hlogAdapter) Infof(format string, v ...interface{}) {
	write(L(), zapcore.InfoLevel, format, v)
}

func (hlogAdapter) Noticef(format string, v ...interface{}) {
	write(L(), zapcore.InfoLevel, format, v)
}

func (hlogAdapter) Warnf(format string, v ...interface{}) {
	write(L(), zapcore.WarnLevel, format, v)
}

func (hlogAdapter) Errorf(format string, v ...interface{}) {
	write(L(), zapcore.ErrorLevel, format, v)
}

func (hlogAdapter) Fatalf(format string, v ...interface{}) {
	write(L(), zapcore.FatalLevel, format, v)
}

func (hlogAdapter) CtxTracef(ctx context.Context, format string, v ...interface{}) {
	write(From(ctx), zapcore.DebugLevel, format, v)
}

func (hlogAdapter) CtxDebugf(ctx context.Context, format string, v ...interface{}) {
	write(From(ctx), zapcore.DebugLevel, format, v)
}

func (hlogAdapter) CtxInfof(ctx context.Context, format string, v ...interface{}) {
	write(From(ctx), zapcore.InfoLevel, format, v)
}

func (hlogAdapter) CtxNoticef(ctx context.Context, format string, v ...interface{}) {
	write(From(ctx), zapcore.InfoLevel, format, v)
}

func (hlogAdapter) CtxWarnf(ctx context.Context, format string, v ...interface{}) {
	write(From(ctx), zapcore.WarnLevel, format, v)
}

func (hlogAdapter) CtxErrorf(ctx context.Context, format string, v ...interface{}) {
	write(From(ctx), zapcore.ErrorLevel, format, v)
}

func (hlogAdapter) CtxFatalf(ctx context.Context, format string, v ...interface{}) {
	write(From(ctx), zapcore.FatalLevel, format, v)
}

// SetLevel maps the hlog level onto the shared package level.
func (hlogAdapter) SetLevel(lv hlog.Level) {
	switch {
	case lv <= hlog.LevelDebug:
		level.SetLevel(zapcore.DebugLevel)
	case lv <= hlog.LevelNotice:
		level.SetLevel(zapcore.InfoLevel)
	case lv == hlog.LevelWarn:
		level.SetLevel(zapcore.WarnLevel)
	case lv == hlog.LevelError:
		level.SetLevel(zapcore.ErrorLevel)
	default:
		level.SetLevel(zapcore.FatalLevel)
	}
}

// SetOutput is a no-op: the output is owned by Init.
func (hlogAdapter) SetOutput(io.Writer) {}
