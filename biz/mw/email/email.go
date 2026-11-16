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

package email

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/authboot/authboot-server/biz/mw/email/provider"
)

// Message and Sender are re-exported from the provider package so callers can
// keep using email.Message / email.Sender without importing the subpackage.
type (
	Message = provider.Message
	Sender  = provider.Sender
)

// defaultSender is the process-wide adapter selected by Init. Business code
// sends mail through the package-level Send, staying decoupled from the vendor.
var defaultSender Sender

// Init selects and initializes the email provider from environment variables.
// It is intended to be called once at startup, alongside the other mw Init()s.
//
// Supported env:
//
//	EMAIL_PROVIDER   provider id, default "smtp"
//
// SMTP provider (EMAIL_PROVIDER=smtp):
//
//	SMTP_HOST        required, e.g. smtp.gmail.com
//	SMTP_PORT        optional, default 587
//	SMTP_USERNAME    optional (enables AUTH when set)
//	SMTP_PASSWORD    optional
//	SMTP_FROM        default From address, e.g. "Authboot <no-reply@authboot.io>"
//	SMTP_USE_TLS     "true" for implicit TLS (port 465); default false (STARTTLS)
//
// Resend provider (EMAIL_PROVIDER=resend):
//
//	RESEND_API_KEY   required, e.g. re_xxx
//	RESEND_FROM      default From address, e.g. "Authboot <no-reply@authboot.io>"
func Init() {
	name := strings.ToLower(strings.TrimSpace(os.Getenv("EMAIL_PROVIDER")))
	if name == "" {
		name = "smtp"
	}

	sender, err := buildSender(name)
	if err != nil {
		log.Fatalf("email 初始化失败: %v", err)
	}
	defaultSender = sender
	log.Printf("email provider initialized: %s", sender.Name())
}

// buildSender constructs the Sender for the given provider id. Add new cases
// here to wire up additional adapters (ses, sendgrid, mailgun, ...).
func buildSender(name string) (Sender, error) {
	switch name {
	case "smtp":
		return newSMTPSenderFromEnv()
	case "resend":
		return newResendSenderFromEnv()
	default:
		return nil, fmt.Errorf("unsupported EMAIL_PROVIDER %q", name)
	}
}

// newSMTPSenderFromEnv reads SMTP_* env vars into a provider.SMTPConfig.
func newSMTPSenderFromEnv() (Sender, error) {
	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	if host == "" {
		return nil, fmt.Errorf("SMTP_HOST is not set")
	}

	port := 587
	if p := strings.TrimSpace(os.Getenv("SMTP_PORT")); p != "" {
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid SMTP_PORT %q: %w", p, err)
		}
		port = v
	}

	useTLS := strings.EqualFold(strings.TrimSpace(os.Getenv("SMTP_USE_TLS")), "true")

	return provider.NewSMTPSender(provider.SMTPConfig{
		Host:     host,
		Port:     port,
		Username: strings.TrimSpace(os.Getenv("SMTP_USERNAME")),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     strings.TrimSpace(os.Getenv("SMTP_FROM")),
		UseTLS:   useTLS,
	}), nil
}

// newResendSenderFromEnv reads RESEND_* env vars into a provider.ResendConfig.
func newResendSenderFromEnv() (Sender, error) {
	apiKey := strings.TrimSpace(os.Getenv("RESEND_API_KEY"))
	if apiKey == "" {
		return nil, fmt.Errorf("RESEND_API_KEY is not set")
	}
	return provider.NewResendSender(provider.ResendConfig{
		APIKey: apiKey,
		From:   strings.TrimSpace(os.Getenv("RESEND_FROM")),
	}), nil
}

// Send delivers a message through the process-wide provider configured by Init.
func Send(ctx context.Context, msg *Message) error {
	if defaultSender == nil {
		return fmt.Errorf("email: not initialized, call email.Init() first")
	}
	return defaultSender.Send(ctx, msg)
}

// SendWith delivers a message through an explicitly supplied sender, bypassing
// the process-wide default. Useful for tests or per-request provider overrides.
func SendWith(ctx context.Context, sender Sender, msg *Message) error {
	if sender == nil {
		return fmt.Errorf("email: sender is nil")
	}
	return sender.Send(ctx, msg)
}
