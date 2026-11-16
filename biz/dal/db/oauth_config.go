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

// OAuthConfig stores one organization's credentials for a single OAuth
// identity provider (wechat / alipay / github / ...). It is a unified table:
// provider-specific fields are not modeled as columns but serialized (and
// encrypted) into Config, so adding a new vendor needs no schema migration.
// The (organization_id, provider) tuple is unique — one config per vendor per
// organization.
type OAuthConfig struct {
	ID             int64  `json:"id" gorm:"primaryKey;autoIncrement"`
	OrganizationID int64  `json:"organization_id" gorm:"column:organization_id;not null;uniqueIndex:uk_org_provider,priority:1"`
	Provider       string `json:"provider" gorm:"column:provider;type:varchar(32);not null;uniqueIndex:uk_org_provider,priority:2"`
	// Config is the encrypted provider config blob (AES-GCM over the vendor's
	// JSON config). Never store the plaintext secret here.
	Config    []byte    `json:"-" gorm:"column:config;type:varbinary(2048);not null"`
	Enabled   int8      `json:"enabled" gorm:"column:enabled;type:tinyint;not null;default:1;index"`
	CreatedAt time.Time `json:"created_at" gorm:"not null"`
	UpdatedAt time.Time `json:"updated_at" gorm:"not null"`
}

func (OAuthConfig) TableName() string {
	return constants.OAuthConfigTableName
}

// OAuthConfigDAO is the data-access handle for the oauth config table. It wraps
// a *gorm.DB so the same methods run on the global connection (via the package
// default instance OAuthConfigs) or inside a transaction (via WithTx).
type OAuthConfigDAO struct {
	db *gorm.DB
}

// NewOAuthConfigDAO builds an OAuthConfigDAO bound to the given connection.
func NewOAuthConfigDAO(db *gorm.DB) *OAuthConfigDAO {
	return &OAuthConfigDAO{db: db}
}

// WithTx returns an OAuthConfigDAO that runs its queries on the given transaction.
func (d *OAuthConfigDAO) WithTx(tx *gorm.DB) *OAuthConfigDAO {
	return &OAuthConfigDAO{db: tx}
}

// QueryOAuthConfig returns the enabled config for (organizationID, provider).
// A missing or disabled row surfaces gorm.ErrRecordNotFound so callers can
// distinguish "not configured" from a real database error.
func (d *OAuthConfigDAO) QueryOAuthConfig(organizationID int64, provider string) (*OAuthConfig, error) {
	var cfg OAuthConfig
	if err := d.db.Where(
		"organization_id = ? AND provider = ? AND enabled = ?",
		organizationID, provider, constants.StatusEnabled,
	).First(&cfg).Error; err != nil {
		return nil, err
	}
	return &cfg, nil
}

// QueryOAuthConfigAny returns the config regardless of its enabled flag — the
// admin read path needs to show disabled configs too.
func (d *OAuthConfigDAO) QueryOAuthConfigAny(organizationID int64, provider string) (*OAuthConfig, error) {
	var cfg OAuthConfig
	if err := d.db.Where(
		"organization_id = ? AND provider = ?",
		organizationID, provider,
	).First(&cfg).Error; err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ListOAuthConfigs returns every provider config of an organization.
func (d *OAuthConfigDAO) ListOAuthConfigs(organizationID int64) ([]*OAuthConfig, error) {
	var cfgs []*OAuthConfig
	if err := d.db.Where("organization_id = ?", organizationID).
		Order("provider asc").Find(&cfgs).Error; err != nil {
		return nil, err
	}
	return cfgs, nil
}

// DeleteOAuthConfig removes an organization's config for a provider.
func (d *OAuthConfigDAO) DeleteOAuthConfig(organizationID int64, provider string) error {
	return d.db.Where("organization_id = ? AND provider = ?", organizationID, provider).
		Delete(&OAuthConfig{}).Error
}

// UpsertOAuthConfig inserts or updates the config row for (organization_id,
// provider), keyed by the unique index. Config must already be encrypted by
// the caller (see oauth.Encrypt).
func (d *OAuthConfigDAO) UpsertOAuthConfig(cfg *OAuthConfig) error {
	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "organization_id"}, {Name: "provider"}},
		DoUpdates: clause.AssignmentColumns([]string{"config", "enabled", "updated_at"}),
	}).Create(cfg).Error
}
