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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cloudwego/hertz/pkg/common/hlog"
	"gorm.io/gorm"

	"github.com/authboot/authboot-server/biz/dal/db"
)

// templateCacheTTL bounds how long a cached compiled template is trusted. It
// is the consistency backstop for multi-instance deployments: an edit made
// through another replica becomes visible here within this window even
// without an explicit InvalidateTemplate.
const templateCacheTTL = 5 * time.Minute

// templateEntry is a cached compiled override. compiled == nil records
// "no override, use the default" so organizations that never customised a
// template do not hit the database on every send.
type templateEntry struct {
	compiled  *Compiled
	expiresAt time.Time
}

var (
	// defaultCompiled caches the built-in templates, compiled once per id.
	defaultCompiled   = map[string]*Compiled{}
	defaultCompiledMu sync.Mutex

	// templateCache maps "orgID:templateID" to *templateEntry.
	templateCache sync.Map
)

func templateKey(orgID int64, id string) string {
	return fmt.Sprintf("%d:%s", orgID, id)
}

// defaultTemplate returns the compiled built-in template for id.
func defaultTemplate(d *TemplateDescriptor) (*Compiled, error) {
	defaultCompiledMu.Lock()
	defer defaultCompiledMu.Unlock()
	if c, ok := defaultCompiled[d.ID]; ok {
		return c, nil
	}
	c, err := d.Compile(d.DefaultSubject, d.DefaultBody())
	if err != nil {
		return nil, fmt.Errorf("email/template: built-in %s is invalid: %w", d.ID, err)
	}
	defaultCompiled[d.ID] = c
	return c, nil
}

// TemplateFor resolves the compiled template an organization uses for id: its
// override when one is saved, else the built-in default. Overrides are cached
// for templateCacheTTL; a row that fails to compile is logged and the default
// is used so a bad override never blocks mail.
func TemplateFor(ctx context.Context, orgID int64, id string) (*Compiled, error) {
	d, ok := LookupTemplate(id)
	if !ok {
		return nil, fmt.Errorf("email/template: unknown template %q", id)
	}
	if orgID == 0 || db.IEmailTemplateDAO == nil {
		return defaultTemplate(d)
	}

	key := templateKey(orgID, d.ID)
	if v, ok := templateCache.Load(key); ok {
		if e := v.(*templateEntry); time.Now().Before(e.expiresAt) {
			if e.compiled != nil {
				return e.compiled, nil
			}
			return defaultTemplate(d)
		}
	}

	entry := &templateEntry{expiresAt: time.Now().Add(templateCacheTTL)}
	row, err := db.IEmailTemplateDAO.Query(orgID, d.ID)
	switch {
	case err == nil:
		c, cerr := d.Compile(row.Subject, row.Body)
		if cerr != nil {
			hlog.CtxWarnf(ctx, "email/template: override %s for org %d is invalid, using default: %v", d.ID, orgID, cerr)
		} else {
			entry.compiled = c
		}
	case errors.Is(err, gorm.ErrRecordNotFound):
		// no override
	default:
		// Transient DB failure: do not cache, fall back for this send only.
		hlog.CtxWarnf(ctx, "email/template: load override %s for org %d failed, using default: %v", d.ID, orgID, err)
		return defaultTemplate(d)
	}
	templateCache.Store(key, entry)

	if entry.compiled != nil {
		return entry.compiled, nil
	}
	return defaultTemplate(d)
}

// RenderFor renders the organization's template for id with data.
func RenderFor(ctx context.Context, orgID int64, id string, data any) (subject, html string, err error) {
	c, err := TemplateFor(ctx, orgID, id)
	if err != nil {
		return "", "", err
	}
	return c.Execute(data)
}

// InvalidateTemplate drops the cached override so the next render reloads it.
// Call after saving or resetting an override.
func InvalidateTemplate(orgID int64, id string) {
	templateCache.Delete(templateKey(orgID, id))
}
