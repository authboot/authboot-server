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

package provider

import (
	"context"
	"fmt"
	"strings"
)

// Message is a provider-agnostic SMS payload. It carries both the template
// fields used by domestic vendors (阿里云 / 腾讯云: SignName + TemplateCode +
// TemplateParam) and a free-form Content field used by content-based providers
// (Twilio, the log provider), so business code never depends on a concrete SMS
// vendor.
type Message struct {
	// PhoneNumbers is the list of recipients. Required.
	// Domestic numbers may be bare (13800138000); international numbers should
	// be E.164 (+8613800138000).
	PhoneNumbers []string
	// SignName is the SMS signature (短信签名), required by template providers.
	SignName string
	// TemplateCode is the approved template id, required by template providers.
	TemplateCode string
	// TemplateParam holds the template variables, e.g. {"code": "1234"}.
	TemplateParam map[string]string
	// Content is a free-form message body used by content-based providers.
	Content string
}

// Sender is the SMS adapter interface. To plug in a new vendor (腾讯云, Twilio,
// ...), implement this interface and register it in Init.
type Sender interface {
	// Send delivers a single message. Implementations should honor ctx for
	// cancellation / timeout where the underlying transport allows it.
	Send(ctx context.Context, msg *Message) error
	// Name returns the provider identifier, used for logging.
	Name() string
}

// validate checks the fields shared by every provider. Provider-specific
// requirements (e.g. template fields) are validated by each adapter.
func (m *Message) validate() error {
	if m == nil {
		return fmt.Errorf("sms: message is nil")
	}
	if len(m.PhoneNumbers) == 0 {
		return fmt.Errorf("sms: at least one recipient (PhoneNumbers) is required")
	}
	for _, p := range m.PhoneNumbers {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("sms: empty phone number in PhoneNumbers")
		}
	}
	return nil
}
