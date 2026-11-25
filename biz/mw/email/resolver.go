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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cloudwego/hertz/pkg/common/hlog"
	"gorm.io/gorm"

	"github.com/authboot/authboot-server/biz/dal/db"
)

// senderCache memoizes the Sender built from an organization's enabled
// provider config. Entries are dropped by Invalidate when the admin saves or
// deletes a config. A nil value means "no org config, use the default".
var senderCache sync.Map // map[int64]Sender

// SenderFor returns the Sender an organization's mail should go through: its
// primary provider with the configured fallbacks tried in order, otherwise
// the process-wide default from .env. Config load/decrypt failures are logged
// and fall back to the default so a bad tenant config never blocks mail.
func SenderFor(ctx context.Context, orgID int64) Sender {
	if orgID == 0 || db.IMessageProviderConfigDAO == nil {
		return defaultSender
	}
	if v, ok := senderCache.Load(orgID); ok {
		if s, _ := v.(Sender); s != nil {
			return s
		}
		return defaultSender
	}
	s, err := loadOrgSender(orgID)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			hlog.CtxWarnf(ctx, "email: load provider for org %d failed, using default: %v", orgID, err)
		}
		senderCache.Store(orgID, Sender(nil))
		return defaultSender
	}
	senderCache.Store(orgID, s)
	return s
}

// SendFor delivers msg through the organization's resolved Sender.
func SendFor(ctx context.Context, orgID int64, msg *Message) error {
	s := SenderFor(ctx, orgID)
	if s == nil {
		return fmt.Errorf("email: not initialized, call email.Init() first")
	}
	return s.Send(ctx, msg)
}

// Invalidate drops the cached Sender for an organization so the next send
// rebuilds from the database.
func Invalidate(orgID int64) {
	senderCache.Delete(orgID)
}

// loadOrgSender reads the active providers of orgID (primary first) and
// builds a failover Sender over them. Rows that fail to decrypt or build are
// skipped with a warning.
func loadOrgSender(orgID int64) (Sender, error) {
	rows, err := db.IMessageProviderConfigDAO.ListActive(orgID, Channel)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	senders := make([]Sender, 0, len(rows))
	for _, row := range rows {
		s, err := buildFromRow(row)
		if err != nil {
			hlog.Warnf("email: skip provider %s for org %d: %v", row.Provider, orgID, err)
			continue
		}
		senders = append(senders, s)
	}
	if len(senders) == 0 {
		return nil, fmt.Errorf("email: no usable provider for org %d", orgID)
	}
	if len(senders) == 1 {
		return senders[0], nil
	}
	return &failoverSender{senders: senders}, nil
}

func buildFromRow(row *db.MessageProviderConfig) (Sender, error) {
	plain, err := Decrypt(row.Config)
	if err != nil {
		return nil, err
	}
	var settings map[string]string
	if err := json.Unmarshal(plain, &settings); err != nil {
		return nil, fmt.Errorf("email: decode provider settings: %w", err)
	}
	return Build(row.Provider, settings)
}

// failoverSender tries each Sender in order and returns on the first success.
// It stops early when ctx is done so a slow primary does not cascade into
// every fallback timing out as well.
type failoverSender struct {
	senders []Sender
}

func (f *failoverSender) Name() string {
	names := make([]string, len(f.senders))
	for i, s := range f.senders {
		names[i] = s.Name()
	}
	return "failover(" + strings.Join(names, ",") + ")"
}

func (f *failoverSender) Send(ctx context.Context, msg *Message) error {
	var errs []error
	for i, s := range f.senders {
		err := s.Send(ctx, msg)
		if err == nil {
			if i > 0 {
				hlog.CtxWarnf(ctx, "email: primary provider failed, delivered via fallback %s", s.Name())
			}
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		if ctx.Err() != nil {
			break
		}
	}
	return fmt.Errorf("email: all providers failed: %w", errors.Join(errs...))
}
