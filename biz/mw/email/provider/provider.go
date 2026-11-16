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

// Package provider holds the email adapter contract (Message + Sender) and the
// concrete vendor implementations (SMTP, Resend, ...). The parent email package
// selects and constructs a Sender; business code stays decoupled from vendors.
package provider

import (
	"context"
	"fmt"
	"mime"
	"strings"
	"time"
)

// Message is a provider-agnostic email payload. All adapters accept this type,
// so business code never depends on a concrete email vendor.
type Message struct {
	// From overrides the provider's default sender. Optional.
	From string
	// To is the list of primary recipients. Required.
	To []string
	// Cc / Bcc are optional carbon-copy recipients.
	Cc  []string
	Bcc []string
	// Subject is the email subject line. Required.
	Subject string
	// HTML is the HTML body. Optional if Text is set.
	HTML string
	// Text is the plaintext body. Optional if HTML is set.
	Text string
	// ReplyTo sets an optional Reply-To header.
	ReplyTo string
}

// Sender is the email adapter interface. To plug in a new provider (SES,
// SendGrid, Mailgun, 阿里云邮件推送 ...), implement this interface and register
// it in the parent package's buildSender.
type Sender interface {
	// Send delivers a single message. Implementations should honor ctx for
	// cancellation / timeout where the underlying transport allows it.
	Send(ctx context.Context, msg *Message) error
	// Name returns the provider identifier, used for logging.
	Name() string
}

// validate checks the minimum required fields before handing off to a provider.
func (m *Message) validate() error {
	if m == nil {
		return fmt.Errorf("email: message is nil")
	}
	if len(m.To) == 0 {
		return fmt.Errorf("email: at least one recipient (To) is required")
	}
	if strings.TrimSpace(m.Subject) == "" {
		return fmt.Errorf("email: subject is required")
	}
	if strings.TrimSpace(m.HTML) == "" && strings.TrimSpace(m.Text) == "" {
		return fmt.Errorf("email: either HTML or Text body is required")
	}
	return nil
}

// allRecipients returns the flattened To + Cc + Bcc list used as SMTP RCPT TO.
func (m *Message) allRecipients() []string {
	out := make([]string, 0, len(m.To)+len(m.Cc)+len(m.Bcc))
	out = append(out, m.To...)
	out = append(out, m.Cc...)
	out = append(out, m.Bcc...)
	return out
}

// buildMIME renders the message into a RFC 5322 / MIME byte payload. It emits a
// multipart/alternative body when both Text and HTML are present, otherwise a
// single-part body with the appropriate Content-Type.
func (m *Message) buildMIME(from string) []byte {
	var b strings.Builder

	writeHeader := func(k, v string) {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\r\n")
	}

	writeHeader("From", from)
	writeHeader("To", strings.Join(m.To, ", "))
	if len(m.Cc) > 0 {
		writeHeader("Cc", strings.Join(m.Cc, ", "))
	}
	if m.ReplyTo != "" {
		writeHeader("Reply-To", m.ReplyTo)
	}
	writeHeader("Subject", encodeSubject(m.Subject))
	writeHeader("Date", time.Now().Format(time.RFC1123Z))
	writeHeader("MIME-Version", "1.0")

	hasHTML := strings.TrimSpace(m.HTML) != ""
	hasText := strings.TrimSpace(m.Text) != ""

	switch {
	case hasHTML && hasText:
		boundary := "authboot-alt-boundary"
		writeHeader("Content-Type", fmt.Sprintf("multipart/alternative; boundary=%q", boundary))
		b.WriteString("\r\n")

		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(m.Text)
		b.WriteString("\r\n\r\n")

		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(m.HTML)
		b.WriteString("\r\n\r\n")

		b.WriteString("--" + boundary + "--\r\n")
	case hasHTML:
		writeHeader("Content-Type", "text/html; charset=UTF-8")
		writeHeader("Content-Transfer-Encoding", "8bit")
		b.WriteString("\r\n")
		b.WriteString(m.HTML)
	default:
		writeHeader("Content-Type", "text/plain; charset=UTF-8")
		writeHeader("Content-Transfer-Encoding", "8bit")
		b.WriteString("\r\n")
		b.WriteString(m.Text)
	}

	return []byte(b.String())
}

// encodeSubject wraps a non-ASCII subject in RFC 2047 encoded-word form so that
// UTF-8 subjects (e.g. Chinese) render correctly across mail clients.
func encodeSubject(s string) string {
	for _, r := range s {
		if r > 127 {
			return mime.BEncoding.Encode("UTF-8", s)
		}
	}
	return s
}
