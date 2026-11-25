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

package db

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authboot/authboot-server/pkg/constants"
)

// MessageProviderConfig stores one organization's credentials for a single
// message delivery provider on a channel (email: resend / smtp; sms: ...).
// Like OAuthConfig, provider-specific fields are serialized and encrypted
// into Config so adding a vendor needs no schema change. The
// (organization_id, channel, provider) tuple is unique. Priority orders the
// enabled rows of a channel: 1 is the primary (default) provider, 2.. are
// fallbacks tried in order, 0 means saved but not used for sending.
type MessageProviderConfig struct {
	ID             int64  `json:"id" gorm:"primaryKey;autoIncrement"`
	OrganizationID int64  `json:"organization_id" gorm:"column:organization_id;not null;uniqueIndex:uk_org_channel_provider,priority:1"`
	Channel        string `json:"channel" gorm:"column:channel;type:varchar(16);not null;uniqueIndex:uk_org_channel_provider,priority:2"`
	Provider       string `json:"provider" gorm:"column:provider;type:varchar(32);not null;uniqueIndex:uk_org_channel_provider,priority:3"`
	// Config is the encrypted provider settings blob (AES-GCM over JSON).
	Config  []byte `json:"-" gorm:"column:config;type:varbinary(4096);not null"`
	Enabled int8   `json:"enabled" gorm:"column:enabled;type:tinyint;not null;default:1;index"`
	// Priority: 1 = primary, 2.. = fallback order, 0 = not in rotation.
	Priority int32 `json:"priority" gorm:"column:priority;not null;default:0;index"`
	// VerifiedAt is when the last validation send succeeded (unix seconds).
	VerifiedAt int64     `json:"verified_at" gorm:"column:verified_at;not null;default:0"`
	CreatedAt  time.Time `json:"created_at" gorm:"not null"`
	UpdatedAt  time.Time `json:"updated_at" gorm:"not null"`
}

func (MessageProviderConfig) TableName() string {
	return constants.MessageProviderConfigTableName
}

// MessageProviderConfigDAO is the data-access handle for the table.
type MessageProviderConfigDAO struct {
	db *gorm.DB
}

// NewMessageProviderConfigDAO builds a DAO bound to the given connection.
func NewMessageProviderConfigDAO(db *gorm.DB) *MessageProviderConfigDAO {
	return &MessageProviderConfigDAO{db: db}
}

// WithTx returns a DAO that runs its queries on the given transaction.
func (d *MessageProviderConfigDAO) WithTx(tx *gorm.DB) *MessageProviderConfigDAO {
	return &MessageProviderConfigDAO{db: tx}
}

// ListActive returns the enabled providers of (organizationID, channel) that
// take part in sending, ordered primary first then fallbacks.
func (d *MessageProviderConfigDAO) ListActive(organizationID int64, channel string) ([]*MessageProviderConfig, error) {
	var cfgs []*MessageProviderConfig
	if err := d.db.Where(
		"organization_id = ? AND channel = ? AND enabled = ? AND priority > 0",
		organizationID, channel, constants.StatusEnabled,
	).Order("priority asc").Find(&cfgs).Error; err != nil {
		return nil, err
	}
	return cfgs, nil
}

// QueryAny returns the config regardless of its enabled flag.
func (d *MessageProviderConfigDAO) QueryAny(organizationID int64, channel, provider string) (*MessageProviderConfig, error) {
	var cfg MessageProviderConfig
	if err := d.db.Where(
		"organization_id = ? AND channel = ? AND provider = ?",
		organizationID, channel, provider,
	).First(&cfg).Error; err != nil {
		return nil, err
	}
	return &cfg, nil
}

// List returns every provider config of an organization, optionally filtered
// by channel (empty channel = all).
func (d *MessageProviderConfigDAO) List(organizationID int64, channel string) ([]*MessageProviderConfig, error) {
	q := d.db.Where("organization_id = ?", organizationID)
	if channel != "" {
		q = q.Where("channel = ?", channel)
	}
	var cfgs []*MessageProviderConfig
	if err := q.Order("channel asc, provider asc").Find(&cfgs).Error; err != nil {
		return nil, err
	}
	return cfgs, nil
}

// Delete removes an organization's config for (channel, provider) and closes
// the gap in the send order, so removing the primary promotes the first
// fallback.
func (d *MessageProviderConfigDAO) Delete(organizationID int64, channel, provider string) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("organization_id = ? AND channel = ? AND provider = ?", organizationID, channel, provider).
			Delete(&MessageProviderConfig{}).Error; err != nil {
			return err
		}
		var rest []*MessageProviderConfig
		if err := tx.Where("organization_id = ? AND channel = ? AND priority > 0", organizationID, channel).
			Order("priority asc").Find(&rest).Error; err != nil {
			return err
		}
		for i, row := range rest {
			if row.Priority == int32(i+1) {
				continue
			}
			if err := tx.Model(row).Update("priority", i+1).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// Upsert inserts or updates cfg as an enabled provider. When the channel has
// no primary yet the row becomes primary (priority 1); otherwise a new row is
// appended after the last fallback, and an existing row keeps its priority.
// Config must already be encrypted by the caller.
func (d *MessageProviderConfigDAO) Upsert(cfg *MessageProviderConfig) error {
	cfg.Enabled = constants.StatusEnabled
	return d.db.Transaction(func(tx *gorm.DB) error {
		var existing MessageProviderConfig
		err := tx.Where("organization_id = ? AND channel = ? AND provider = ?",
			cfg.OrganizationID, cfg.Channel, cfg.Provider).First(&existing).Error
		switch {
		case err == nil:
			cfg.Priority = existing.Priority
		case err == gorm.ErrRecordNotFound:
			var maxPriority int32
			if err := tx.Model(&MessageProviderConfig{}).
				Where("organization_id = ? AND channel = ?", cfg.OrganizationID, cfg.Channel).
				Select("COALESCE(MAX(priority), 0)").Scan(&maxPriority).Error; err != nil {
				return err
			}
			cfg.Priority = maxPriority + 1
		default:
			return err
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "organization_id"}, {Name: "channel"}, {Name: "provider"}},
			DoUpdates: clause.AssignmentColumns([]string{"config", "enabled", "priority", "verified_at", "updated_at"}),
		}).Create(cfg).Error
	})
}

// SetPriorities rewrites the send order of a channel: order[0] becomes the
// primary, the rest fallbacks in sequence; every other row of the channel is
// set to priority 0. Returns gorm.ErrRecordNotFound when a provider in order
// has no saved config.
func (d *MessageProviderConfigDAO) SetPriorities(organizationID int64, channel string, order []string) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&MessageProviderConfig{}).
			Where("organization_id = ? AND channel = ?", organizationID, channel).
			Update("priority", 0).Error; err != nil {
			return err
		}
		for i, provider := range order {
			res := tx.Model(&MessageProviderConfig{}).
				Where("organization_id = ? AND channel = ? AND provider = ?", organizationID, channel, provider).
				Updates(map[string]interface{}{"priority": i + 1, "enabled": constants.StatusEnabled})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				return gorm.ErrRecordNotFound
			}
		}
		return nil
	})
}
