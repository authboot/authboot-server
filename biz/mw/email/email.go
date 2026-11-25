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

// defaultProviderID is the id of the provider Init selected from .env; the
// catalog flags it as the platform default.
var defaultProviderID string

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
//
// Alibaba Cloud DirectMail (EMAIL_PROVIDER=aliyun_dm):
//
//	ALIYUN_DM_ACCESS_KEY_ID / ALIYUN_DM_ACCESS_KEY_SECRET   required
//	ALIYUN_DM_REGION          optional, default cn-hangzhou
//	ALIYUN_DM_SENDER_ADDRESS  required, verified sender address
//	ALIYUN_DM_SENDER_NAME     optional display name
//
// Tencent Cloud SES (EMAIL_PROVIDER=tencent_ses):
//
//	TENCENT_SES_SECRET_ID / TENCENT_SES_SECRET_KEY   required
//	TENCENT_SES_REGION          required, e.g. ap-guangzhou
//	TENCENT_SES_SENDER_ADDRESS  required, e.g. "Acme <noreply@mail.example.com>"
//	TENCENT_SES_TEMPLATE_ID     optional approved template id
func Init() {
	name := strings.ToLower(strings.TrimSpace(os.Getenv("EMAIL_PROVIDER")))
	if name == "" {
		name = "smtp"
	}

	sender, err := Build(name, settingsFromEnv(name))
	if err != nil {
		log.Fatalf("email 初始化失败: %v", err)
	}
	defaultSender = sender
	defaultProviderID = name
	log.Printf("email provider initialized: %s", sender.Name())
}

// DefaultProviderID returns the provider id selected from .env by Init.
func DefaultProviderID() string { return defaultProviderID }

// settingsFromEnv maps the legacy per-vendor env vars onto the registry's
// settings keys so the .env path and the per-organization path share one
// construction routine.
func settingsFromEnv(name string) map[string]string {
	switch name {
	case "smtp":
		return map[string]string{
			"host":     os.Getenv("SMTP_HOST"),
			"port":     os.Getenv("SMTP_PORT"),
			"username": os.Getenv("SMTP_USERNAME"),
			"password": os.Getenv("SMTP_PASSWORD"),
			"from":     os.Getenv("SMTP_FROM"),
			"use_tls":  os.Getenv("SMTP_USE_TLS"),
		}
	case "resend":
		return map[string]string{
			"api_key": os.Getenv("RESEND_API_KEY"),
			"from":    os.Getenv("RESEND_FROM"),
		}
	case "aliyun_dm":
		return map[string]string{
			"access_key_id":     os.Getenv("ALIYUN_DM_ACCESS_KEY_ID"),
			"access_key_secret": os.Getenv("ALIYUN_DM_ACCESS_KEY_SECRET"),
			"region":            os.Getenv("ALIYUN_DM_REGION"),
			"sender_address":    os.Getenv("ALIYUN_DM_SENDER_ADDRESS"),
			"sender_name":       os.Getenv("ALIYUN_DM_SENDER_NAME"),
		}
	case "tencent_ses":
		return map[string]string{
			"secret_id":      os.Getenv("TENCENT_SES_SECRET_ID"),
			"secret_key":     os.Getenv("TENCENT_SES_SECRET_KEY"),
			"region":         os.Getenv("TENCENT_SES_REGION"),
			"sender_address": os.Getenv("TENCENT_SES_SENDER_ADDRESS"),
			"template_id":    os.Getenv("TENCENT_SES_TEMPLATE_ID"),
		}
	default:
		return nil
	}
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
