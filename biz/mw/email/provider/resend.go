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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// defaultResendEndpoint is the Resend transactional email API endpoint.
const defaultResendEndpoint = "https://api.resend.com/emails"

// ResendConfig holds the credentials for the Resend (resend.com) adapter.
type ResendConfig struct {
	APIKey string // Resend API key, e.g. re_xxx
	// From is the default sender used when Message.From is empty. Must be a
	// verified domain/address on the Resend account, e.g. "Authboot <no-reply@authboot.io>".
	From string
	// Endpoint overrides the API endpoint; defaults to defaultResendEndpoint.
	Endpoint string
	// Timeout bounds the HTTP request.
	Timeout time.Duration
}

// resendSender implements Sender against the Resend HTTP API. It uses only the
// standard library, so no vendor SDK dependency is introduced.
type resendSender struct {
	cfg    ResendConfig
	client *http.Client
}

// NewResendSender builds a Resend-backed Sender.
func NewResendSender(cfg ResendConfig) Sender {
	if cfg.Endpoint == "" {
		cfg.Endpoint = defaultResendEndpoint
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &resendSender{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

func (s *resendSender) Name() string { return "resend" }

// resendPayload mirrors the Resend "send email" request body.
type resendPayload struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Cc      []string `json:"cc,omitempty"`
	Bcc     []string `json:"bcc,omitempty"`
	ReplyTo string   `json:"reply_to,omitempty"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html,omitempty"`
	Text    string   `json:"text,omitempty"`
}

func (s *resendSender) Send(ctx context.Context, msg *Message) error {
	if err := msg.validate(); err != nil {
		return err
	}

	from := msg.From
	if from == "" {
		from = s.cfg.From
	}
	if from == "" {
		return fmt.Errorf("email/resend: no From address (set Message.From or ResendConfig.From)")
	}
	if s.cfg.APIKey == "" {
		return fmt.Errorf("email/resend: APIKey is required")
	}

	payload := resendPayload{
		From:    from,
		To:      msg.To,
		Cc:      msg.Cc,
		Bcc:     msg.Bcc,
		ReplyTo: msg.ReplyTo,
		Subject: msg.Subject,
		HTML:    msg.HTML,
		Text:    msg.Text,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("email/resend: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("email/resend: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("email/resend: request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Resend returns {"statusCode":..,"name":"..","message":".."} on error.
		var e struct {
			Name    string `json:"name"`
			Message string `json:"message"`
		}
		if json.Unmarshal(respBody, &e) == nil && e.Message != "" {
			return fmt.Errorf("email/resend: send failed (status %d): %s: %s", resp.StatusCode, e.Name, e.Message)
		}
		return fmt.Errorf("email/resend: send failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}
