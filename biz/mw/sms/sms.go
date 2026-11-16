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

package sms

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/authboot/authboot-server/biz/mw/sms/provider"
)

// Message and Sender are re-exported from the provider package so callers can
// keep using sms.Message / sms.Sender without importing the subpackage.
type (
	Message = provider.Message
	Sender  = provider.Sender
)

// defaultSender is the process-wide adapter selected by Init. Business code
// sends messages through the package-level Send, staying decoupled from the vendor.
var defaultSender Sender

// Init selects and initializes the SMS provider from environment variables.
// It is intended to be called once at startup, alongside the other mw Init()s.
//
// Supported env:
//
//	SMS_PROVIDER     provider id, default "log"
//
// aliyun provider (SMS_PROVIDER=aliyun):
//
//	SMS_ALIYUN_ACCESS_KEY_ID      required
//	SMS_ALIYUN_ACCESS_KEY_SECRET  required
//	SMS_ALIYUN_SIGN_NAME          default 短信签名
//	SMS_ALIYUN_REGION_ID          optional, default cn-hangzhou
//	SMS_ALIYUN_ENDPOINT           optional, default dysmsapi.aliyuncs.com
func Init() {
	name := strings.ToLower(strings.TrimSpace(os.Getenv("SMS_PROVIDER")))
	if name == "" {
		name = "log"
	}

	sender, err := buildSender(name)
	if err != nil {
		log.Fatalf("sms 初始化失败: %v", err)
	}
	defaultSender = sender
	log.Printf("sms provider initialized: %s", sender.Name())
}

// buildSender constructs the Sender for the given provider id. Add new cases
// here to wire up additional adapters (tencent, twilio, ...).
func buildSender(name string) (Sender, error) {
	switch name {
	case "log":
		return provider.NewLogSender(), nil
	case "aliyun":
		return newAliyunSenderFromEnv()
	default:
		return nil, fmt.Errorf("unsupported SMS_PROVIDER %q", name)
	}
}

// newAliyunSenderFromEnv reads SMS_ALIYUN_* env vars into a provider.AliyunConfig.
func newAliyunSenderFromEnv() (Sender, error) {
	keyID := strings.TrimSpace(os.Getenv("SMS_ALIYUN_ACCESS_KEY_ID"))
	if keyID == "" {
		return nil, fmt.Errorf("SMS_ALIYUN_ACCESS_KEY_ID is not set")
	}
	secret := os.Getenv("SMS_ALIYUN_ACCESS_KEY_SECRET")
	if strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("SMS_ALIYUN_ACCESS_KEY_SECRET is not set")
	}

	return provider.NewAliyunSender(provider.AliyunConfig{
		AccessKeyID:     keyID,
		AccessKeySecret: secret,
		SignName:        strings.TrimSpace(os.Getenv("SMS_ALIYUN_SIGN_NAME")),
		RegionID:        strings.TrimSpace(os.Getenv("SMS_ALIYUN_REGION_ID")),
		Endpoint:        strings.TrimSpace(os.Getenv("SMS_ALIYUN_ENDPOINT")),
	}), nil
}

// Send delivers a message through the process-wide provider configured by Init.
func Send(ctx context.Context, msg *Message) error {
	if defaultSender == nil {
		return fmt.Errorf("sms: not initialized, call sms.Init() first")
	}
	return defaultSender.Send(ctx, msg)
}

// SendWith delivers a message through an explicitly supplied sender, bypassing
// the process-wide default. Useful for tests or per-request provider overrides.
func SendWith(ctx context.Context, sender Sender, msg *Message) error {
	if sender == nil {
		return fmt.Errorf("sms: sender is nil")
	}
	return sender.Send(ctx, msg)
}
