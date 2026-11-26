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
	"bytes"
	"fmt"
	htmltemplate "html/template"
	"sort"
	"strings"
	texttemplate "text/template"
)

// Limits applied to tenant-supplied templates. Mirror the admin UI constants.
const (
	TemplateSubjectMax = 120
	TemplateBodyMax    = 20000
)

// TemplateVariable declares a value available to a template as {{.Name}}.
type TemplateVariable struct {
	Name        string
	Description string
	// Sample stands in for the real value in previews and test mails.
	Sample string
	// Required means the body must reference the variable.
	Required bool
}

// TemplateDescriptor is a registered system email: its id, when it is sent,
// the variables the sender has at hand, and the built-in default wording.
// The default body lives in templates/<id>.html.
type TemplateDescriptor struct {
	ID             string
	Name           string
	Trigger        string
	Variables      []TemplateVariable
	DefaultSubject string
}

// DefaultBody returns the embedded default HTML for the template.
func (d *TemplateDescriptor) DefaultBody() string {
	b, err := templateFS.ReadFile("templates/" + d.ID + ".html")
	if err != nil {
		return ""
	}
	return string(b)
}

// SampleData builds the preview data map from the variables' samples.
func (d *TemplateDescriptor) SampleData() map[string]any {
	out := make(map[string]any, len(d.Variables))
	for _, v := range d.Variables {
		out[v.Name] = v.Sample
	}
	return out
}

// Compiled is a parsed subject + body pair ready to execute.
type Compiled struct {
	subject *texttemplate.Template
	body    *htmltemplate.Template
}

// Execute renders both parts with data.
func (c *Compiled) Execute(data any) (subject, html string, err error) {
	var sb, bb bytes.Buffer
	if err := c.subject.Execute(&sb, data); err != nil {
		return "", "", fmt.Errorf("email/template: render subject: %w", err)
	}
	if err := c.body.Execute(&bb, data); err != nil {
		return "", "", fmt.Errorf("email/template: render body: %w", err)
	}
	return strings.TrimSpace(sb.String()), bb.String(), nil
}

// Compile parses and validates a subject/body pair for the descriptor: size
// limits, template syntax, required variables, and a dry run with the sample
// data so runtime execution cannot fail on a template that passed here. The
// subject is a text template (no HTML escaping), the body an html template.
func (d *TemplateDescriptor) Compile(subject, body string) (*Compiled, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, fmt.Errorf("email/template: subject is required")
	}
	if len([]rune(subject)) > TemplateSubjectMax {
		return nil, fmt.Errorf("email/template: subject exceeds %d characters", TemplateSubjectMax)
	}
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("email/template: body is required")
	}
	if len([]rune(body)) > TemplateBodyMax {
		return nil, fmt.Errorf("email/template: body exceeds %d characters", TemplateBodyMax)
	}
	for _, v := range d.Variables {
		if v.Required && !strings.Contains(body, "."+v.Name) {
			return nil, fmt.Errorf("email/template: body must include {{.%s}}", v.Name)
		}
	}
	// missingkey=error rejects references to variables the sender does not
	// provide, which would otherwise render as "<no value>".
	st, err := texttemplate.New(d.ID + ":subject").Option("missingkey=error").Parse(subject)
	if err != nil {
		return nil, fmt.Errorf("email/template: subject: %w", err)
	}
	bt, err := htmltemplate.New(d.ID + ":body").Option("missingkey=error").Parse(body)
	if err != nil {
		return nil, fmt.Errorf("email/template: body: %w", err)
	}
	c := &Compiled{subject: st, body: bt}
	if _, _, err := c.Execute(d.SampleData()); err != nil {
		return nil, err
	}
	return c, nil
}

// templateRegistry holds every system email keyed by id.
var templateRegistry = map[string]*TemplateDescriptor{}

// RegisterTemplate adds a system email to the catalog.
func RegisterTemplate(d *TemplateDescriptor) {
	templateRegistry[d.ID] = d
}

// LookupTemplate returns the descriptor for a template id.
func LookupTemplate(id string) (*TemplateDescriptor, bool) {
	d, ok := templateRegistry[strings.ToLower(strings.TrimSpace(id))]
	return d, ok
}

// TemplateCatalog returns all registered templates sorted by id.
func TemplateCatalog() []*TemplateDescriptor {
	out := make([]*TemplateDescriptor, 0, len(templateRegistry))
	for _, d := range templateRegistry {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func init() {
	RegisterTemplate(&TemplateDescriptor{
		ID:      "verification_code",
		Name:    "Verification code",
		Trigger: "Sent when a user asks for an email code to sign in, sign up, bind an email address, reset a password or delete their account.",
		Variables: []TemplateVariable{
			{Name: "Code", Description: "The 6-digit one-time code.", Sample: "482913", Required: true},
			{Name: "ExpireMinutes", Description: "How many minutes the code stays valid.", Sample: "5"},
		},
		DefaultSubject: "你的验证码",
	})
	RegisterTemplate(&TemplateDescriptor{
		ID:      "invitation",
		Name:    "Workspace invitation",
		Trigger: "Sent to the email address an admin invites to join this workspace.",
		Variables: []TemplateVariable{
			{Name: "Token", Description: "The invitation token the invitee uses to accept.", Sample: "b7f3c1e09a4d4f2e8c6a1d5e3f9b2a70", Required: true},
			{Name: "ExpireAt", Description: "When the invitation expires.", Sample: "2026-12-02 09:30:00"},
		},
		DefaultSubject: "You have been invited to join an organization",
	})
	RegisterTemplate(&TemplateDescriptor{
		ID:      "security_alert",
		Name:    "Sign-in security alert",
		Trigger: "Sent to a user when a sign-in security event, such as a sign-in from a new device, is recorded on their account.",
		Variables: []TemplateVariable{
			{Name: "Kind", Description: "The type of security event.", Sample: "new_device"},
			{Name: "Time", Description: "When the sign-in happened (UTC).", Sample: "2026-11-25T09:58:00Z"},
			{Name: "IP", Description: "The IP address the sign-in came from.", Sample: "203.0.113.24"},
			{Name: "Location", Description: "The approximate location of that IP address.", Sample: "Shanghai, China"},
		},
		DefaultSubject: "账户登录安全提醒",
	})
}
