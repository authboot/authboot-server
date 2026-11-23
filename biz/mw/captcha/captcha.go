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

package captcha

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/mojocn/base64Captcha"
)

// Config controls how captchas are generated. Zero values fall back to the
// package defaults in Setup.
type Config struct {
	// Type selects the captcha driver: "digit" (default), "string", or "math".
	Type string
	// Height / Width are the PNG dimensions in pixels.
	Height int
	Width  int
	// Length is the number of characters (ignored by the math driver).
	Length int
	// Expiration is how long a generated captcha stays valid.
	Expiration time.Duration
}

const (
	defaultType       = "digit"
	defaultHeight     = 80
	defaultWidth      = 240
	defaultLength     = 5
	defaultExpiration = 5 * time.Minute
	// stringSource is the character set used by the "string" driver.
	stringSource = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
)

var (
	// defaultCaptcha is the process-wide instance built by Init/Setup.
	defaultCaptcha *base64Captcha.Captcha
	// expiration mirrors the configured TTL so ExpireSeconds can report it.
	expiration = defaultExpiration
)

// Init builds the process-wide captcha from environment variables. Intended to
// be called once at startup, alongside the other mw Init()s.
//
// Supported env (all optional):
//
//	CAPTCHA_TYPE            digit | string | math   (default digit)
//	CAPTCHA_HEIGHT         PNG height, default 80
//	CAPTCHA_WIDTH          PNG width, default 240
//	CAPTCHA_LENGTH         char count, default 5
//	CAPTCHA_EXPIRE_SECONDS validity in seconds, default 300
func Init() {
	Setup(configFromEnv())
}

// Setup builds the process-wide captcha from an explicit config. Useful for
// tests or programmatic configuration.
func Setup(cfg Config) {
	cfg = withDefaults(cfg)
	expiration = cfg.Expiration

	store := redis.CaptchaStore{TTL: cfg.Expiration}
	defaultCaptcha = base64Captcha.NewCaptcha(newDriver(cfg), store)
}

// newDriver maps a Config into a base64Captcha driver.
func newDriver(cfg Config) base64Captcha.Driver {
	showLine := base64Captcha.OptionShowHollowLine | base64Captcha.OptionShowSlimeLine
	switch strings.ToLower(cfg.Type) {
	case "string":
		return base64Captcha.NewDriverString(cfg.Height, cfg.Width, 0, showLine, cfg.Length, stringSource, nil, nil)
	case "math":
		return base64Captcha.NewDriverMath(cfg.Height, cfg.Width, 0, showLine, nil, nil)
	default: // digit
		return base64Captcha.NewDriverDigit(cfg.Height, cfg.Width, cfg.Length, 0.7, 80)
	}
}

// Generate creates a new captcha, returning its id and a base64-encoded PNG
// data URI (data:image/png;base64,...). The expected answer is stored server
// side and later checked via Verify.
func Generate() (id, b64s string, err error) {
	if defaultCaptcha == nil {
		return "", "", fmt.Errorf("captcha: not initialized, call captcha.Init() first")
	}
	return defaultCaptcha.Generate()
}

// Verify checks an answer against the stored captcha. When clear is true the
// captcha is consumed (removed) regardless of the result, which is the usual
// choice to prevent replay.
func Verify(id, answer string, clear bool) bool {
	if defaultCaptcha == nil {
		return false
	}
	return defaultCaptcha.Verify(id, answer, clear)
}

// ExpireSeconds returns the configured captcha TTL in seconds, for populating
// API responses such as CreateCaptchaResponse.expire_seconds.
func ExpireSeconds() int {
	return int(expiration / time.Second)
}

// configFromEnv reads the CAPTCHA_* environment variables into a Config.
func configFromEnv() Config {
	return Config{
		Type:       strings.TrimSpace(os.Getenv("CAPTCHA_TYPE")),
		Height:     getenvInt("CAPTCHA_HEIGHT", 0),
		Width:      getenvInt("CAPTCHA_WIDTH", 0),
		Length:     getenvInt("CAPTCHA_LENGTH", 0),
		Expiration: time.Duration(getenvInt("CAPTCHA_EXPIRE_SECONDS", 0)) * time.Second,
	}
}

// withDefaults fills unset (zero) config fields with the package defaults.
func withDefaults(cfg Config) Config {
	if cfg.Type == "" {
		cfg.Type = defaultType
	}
	if cfg.Height <= 0 {
		cfg.Height = defaultHeight
	}
	if cfg.Width <= 0 {
		cfg.Width = defaultWidth
	}
	if cfg.Length <= 0 {
		cfg.Length = defaultLength
	}
	if cfg.Expiration <= 0 {
		cfg.Expiration = defaultExpiration
	}
	return cfg
}

// getenvInt reads an integer env var, returning def when unset or unparsable.
func getenvInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
