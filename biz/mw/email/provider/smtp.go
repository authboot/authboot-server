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
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"time"
)

// SMTPConfig holds the connection parameters for the SMTP adapter.
type SMTPConfig struct {
	Host     string // SMTP server host, e.g. smtp.gmail.com
	Port     int    // SMTP server port, e.g. 587 (STARTTLS) or 465 (implicit TLS)
	Username string // auth username; empty disables AUTH
	Password string // auth password / app token
	From     string // default From address used when Message.From is empty
	// UseTLS forces an implicit TLS connection on dial (typically port 465).
	// When false the adapter dials plaintext and upgrades via STARTTLS if the
	// server advertises it (typically port 587).
	UseTLS bool
	// Timeout bounds the whole dial + send cycle.
	Timeout time.Duration
}

// smtpSender is the net/smtp based implementation of Sender.
type smtpSender struct {
	cfg SMTPConfig
}

// NewSMTPSender builds an SMTP-backed Sender.
func NewSMTPSender(cfg SMTPConfig) Sender {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &smtpSender{cfg: cfg}
}

func (s *smtpSender) Name() string { return "smtp" }

func (s *smtpSender) Send(ctx context.Context, msg *Message) error {
	if err := msg.validate(); err != nil {
		return err
	}

	from := msg.From
	if from == "" {
		from = s.cfg.From
	}
	if from == "" {
		return fmt.Errorf("email/smtp: no From address (set Message.From or SMTPConfig.From)")
	}

	payload := msg.buildMIME(from)
	addr := net.JoinHostPort(s.cfg.Host, fmt.Sprintf("%d", s.cfg.Port))

	// Honor ctx: cap the operation with a deadline derived from ctx or Timeout.
	deadline := time.Now().Add(s.cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	client, cleanup, err := s.dial(ctx, addr, deadline)
	if err != nil {
		return fmt.Errorf("email/smtp: dial %s: %w", addr, err)
	}
	defer cleanup()

	// Upgrade to TLS via STARTTLS when not already on an implicit-TLS socket.
	if !s.cfg.UseTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: s.cfg.Host}); err != nil {
				return fmt.Errorf("email/smtp: starttls: %w", err)
			}
		}
	}

	// Authenticate when credentials are provided.
	if s.cfg.Username != "" {
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("email/smtp: auth: %w", err)
			}
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("email/smtp: MAIL FROM: %w", err)
	}
	for _, rcpt := range msg.allRecipients() {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("email/smtp: RCPT TO %s: %w", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("email/smtp: DATA: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("email/smtp: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email/smtp: close body: %w", err)
	}

	return client.Quit()
}

// dial opens an SMTP client, using an implicit TLS socket when UseTLS is set.
func (s *smtpSender) dial(ctx context.Context, addr string, deadline time.Time) (*smtp.Client, func(), error) {
	netDialer := &net.Dialer{Deadline: deadline}
	var conn net.Conn
	var err error
	if s.cfg.UseTLS {
		dialer := &tls.Dialer{NetDialer: netDialer, Config: &tls.Config{ServerName: s.cfg.Host}}
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = netDialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, nil, err
	}
	return smtpClient(ctx, conn, s.cfg.Host, deadline)
}

// Set the deadline before reading the greeting, for BOTH TLS and plaintext.
// It remains on the underlying socket through STARTTLS and all SMTP commands.
func smtpClient(ctx context.Context, conn net.Conn, host string, deadline time.Time) (*smtp.Client, func(), error) {
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	cleanup := func() { stop(); _ = conn.Close() }
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return client, cleanup, nil
}
