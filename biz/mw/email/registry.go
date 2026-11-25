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
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/authboot/authboot-server/biz/mw/email/provider"
)

// Channel is the delivery channel id used in tb_message_provider_configs and
// the admin API path. The email package only ever registers "email".
const Channel = "email"

// Field declares one setting a provider needs. The admin UI renders a form
// from these; the service uses Secret to mask values on read and to let an
// update omit an unchanged credential.
type Field struct {
	Name        string
	Label       string
	Type        string // text / password / number / boolean
	Secret      bool
	Required    bool
	Placeholder string
}

// Descriptor is a registered email provider: its id, user-facing metadata, the
// settings it accepts and how to turn those settings into a Sender.
type Descriptor struct {
	ID          string
	Name        string
	Description string
	Fields      []Field
	Build       func(settings map[string]string) (Sender, error)
	// TenantCheck, when set, rejects settings that are acceptable for the
	// platform operator (.env) but not for a tenant, e.g. SMTP hosts on
	// private networks. The admin save path runs it; Init does not.
	TenantCheck func(settings map[string]string) error
}

// Validate checks required fields and field types against the declaration.
func (d *Descriptor) Validate(settings map[string]string) error {
	for _, f := range d.Fields {
		v := strings.TrimSpace(settings[f.Name])
		if v == "" {
			if f.Required {
				return fmt.Errorf("email/%s: %s is required", d.ID, f.Name)
			}
			continue
		}
		switch f.Type {
		case "number":
			if _, err := strconv.Atoi(v); err != nil {
				return fmt.Errorf("email/%s: %s must be a number", d.ID, f.Name)
			}
		case "boolean":
			if _, err := strconv.ParseBool(v); err != nil {
				return fmt.Errorf("email/%s: %s must be true or false", d.ID, f.Name)
			}
		}
	}
	return nil
}

// registry holds every known provider keyed by id.
var registry = map[string]*Descriptor{}

// Register adds a provider to the catalog. Called from init() of this package;
// exposed so tests or plugins can add adapters.
func Register(d *Descriptor) {
	registry[d.ID] = d
}

// Lookup returns the descriptor for a provider id (case-insensitive).
func Lookup(id string) (*Descriptor, bool) {
	d, ok := registry[strings.ToLower(strings.TrimSpace(id))]
	return d, ok
}

// Catalog returns all registered providers sorted by id.
func Catalog() []*Descriptor {
	out := make([]*Descriptor, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Build validates settings against the descriptor and constructs the Sender.
func Build(id string, settings map[string]string) (Sender, error) {
	d, ok := Lookup(id)
	if !ok {
		return nil, fmt.Errorf("email: unsupported provider %q", id)
	}
	if err := d.Validate(settings); err != nil {
		return nil, err
	}
	return d.Build(settings)
}

func init() {
	Register(&Descriptor{
		ID:          "resend",
		Name:        "Resend",
		Description: "resend.com transactional email API",
		Fields: []Field{
			{Name: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true, Placeholder: "re_xxx"},
			{Name: "from", Label: "From", Type: "text", Required: true, Placeholder: "Authboot <no-reply@example.com>"},
		},
		Build: func(s map[string]string) (Sender, error) {
			return provider.NewResendSender(provider.ResendConfig{
				APIKey: strings.TrimSpace(s["api_key"]),
				From:   strings.TrimSpace(s["from"]),
			}), nil
		},
	})

	Register(&Descriptor{
		ID:          "smtp",
		Name:        "SMTP",
		Description: "Any SMTP server (STARTTLS on 587 or implicit TLS on 465)",
		Fields: []Field{
			{Name: "host", Label: "Host", Type: "text", Required: true, Placeholder: "smtp.example.com"},
			{Name: "port", Label: "Port", Type: "number", Placeholder: "587"},
			{Name: "username", Label: "Username", Type: "text"},
			{Name: "password", Label: "Password", Type: "password", Secret: true},
			{Name: "from", Label: "From", Type: "text", Required: true, Placeholder: "Authboot <no-reply@example.com>"},
			{Name: "use_tls", Label: "Implicit TLS", Type: "boolean", Placeholder: "false"},
		},
		Build: func(s map[string]string) (Sender, error) {
			host := strings.TrimSpace(s["host"])
			port := 587
			if p := strings.TrimSpace(s["port"]); p != "" {
				port, _ = strconv.Atoi(p) // already validated by Descriptor.Validate
			}
			useTLS, _ := strconv.ParseBool(strings.TrimSpace(s["use_tls"]))
			return provider.NewSMTPSender(provider.SMTPConfig{
				Host:     host,
				Port:     port,
				Username: strings.TrimSpace(s["username"]),
				Password: s["password"],
				From:     strings.TrimSpace(s["from"]),
				UseTLS:   useTLS,
			}), nil
		},
		TenantCheck: func(s map[string]string) error {
			port := 587
			if p := strings.TrimSpace(s["port"]); p != "" {
				port, _ = strconv.Atoi(p)
			}
			return checkSMTPTarget(strings.TrimSpace(s["host"]), port)
		},
	})

	Register(&Descriptor{
		ID:          "aliyun_dm",
		Name:        "Alibaba Cloud Direct Mail",
		Description: "Aliyun DirectMail (邮件推送)",
		Fields: []Field{
			{Name: "access_key_id", Label: "AccessKey ID", Type: "text", Required: true, Placeholder: "LTAI..."},
			{Name: "access_key_secret", Label: "AccessKey Secret", Type: "password", Secret: true, Required: true},
			{Name: "region", Label: "Region", Type: "text", Placeholder: "cn-hangzhou"},
			{Name: "sender_address", Label: "Sender address", Type: "text", Required: true, Placeholder: "noreply@mail.example.com"},
			{Name: "sender_name", Label: "Sender name", Type: "text", Placeholder: "Acme"},
		},
		Build: func(s map[string]string) (Sender, error) {
			return provider.NewAliyunDMSender(provider.AliyunDMConfig{
				AccessKeyID:     strings.TrimSpace(s["access_key_id"]),
				AccessKeySecret: strings.TrimSpace(s["access_key_secret"]),
				Region:          strings.TrimSpace(s["region"]),
				SenderAddress:   strings.TrimSpace(s["sender_address"]),
				SenderName:      strings.TrimSpace(s["sender_name"]),
			}), nil
		},
	})

	Register(&Descriptor{
		ID:          "tencent_ses",
		Name:        "Tencent Cloud SES",
		Description: "Tencent Cloud Simple Email Service (邮件推送)",
		Fields: []Field{
			{Name: "secret_id", Label: "SecretId", Type: "text", Required: true, Placeholder: "AKID..."},
			{Name: "secret_key", Label: "SecretKey", Type: "password", Secret: true, Required: true},
			{Name: "region", Label: "Region", Type: "text", Required: true, Placeholder: "ap-guangzhou"},
			{Name: "sender_address", Label: "Sender address", Type: "text", Required: true, Placeholder: "Acme <noreply@mail.example.com>"},
			{Name: "template_id", Label: "Template ID", Type: "number", Placeholder: "12345"},
		},
		Build: func(s map[string]string) (Sender, error) {
			var templateID int64
			if t := strings.TrimSpace(s["template_id"]); t != "" {
				templateID, _ = strconv.ParseInt(t, 10, 64) // validated as number
			}
			return provider.NewTencentSESSender(provider.TencentSESConfig{
				SecretID:      strings.TrimSpace(s["secret_id"]),
				SecretKey:     strings.TrimSpace(s["secret_key"]),
				Region:        strings.TrimSpace(s["region"]),
				SenderAddress: strings.TrimSpace(s["sender_address"]),
				TemplateID:    templateID,
			}), nil
		},
	})
}
