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
	"log"
	"strings"
)

// logSender is a no-op adapter that writes messages to the application log
// instead of dispatching them. It needs no credentials and always succeeds,
// which makes it the safe default for local development and tests.
type logSender struct{}

// NewLogSender builds a Sender that logs messages instead of sending them.
func NewLogSender() Sender { return &logSender{} }

func (s *logSender) Name() string { return "log" }

func (s *logSender) Send(ctx context.Context, msg *Message) error {
	if err := msg.validate(); err != nil {
		return err
	}
	body := msg.Content
	if body == "" {
		// Render the template fields for a readable dev log line.
		parts := make([]string, 0, len(msg.TemplateParam))
		for k, v := range msg.TemplateParam {
			parts = append(parts, k+"="+v)
		}
		body = "sign=" + msg.SignName + " template=" + msg.TemplateCode +
			" params={" + strings.Join(parts, ",") + "}"
	}
	log.Printf("[sms:log] to=%s %s", strings.Join(msg.PhoneNumbers, ","), body)
	return nil
}
