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
	"errors"

	"gorm.io/gorm"

	"github.com/authboot/authboot-server/pkg/constants"
)

// Organization legal documents (user agreement / privacy policy) follow the
// dashboard's Legal model: a document is an IMMUTABLE, APPEND-ONLY version
// history. Publishing appends a new version and retires the previously active
// one; versions are never edited or deleted (compliance evidence). Each
// version carries the public URL, a change summary, its effective time, the
// publisher, and an optional archived content snapshot with a hash.

// ErrLegalDocNotExist mirrors a "no version published yet" lookup miss.
var ErrLegalDocNotExist = errors.New("legal doc version not found")

// legal doc types stored in tb_organization_legal_doc_versions.doc_type.
// The dashboard UI calls them terms / privacy; the backend stores canonical
// names and the BFF maps between the two.
const (
	LegalDocTypeUserAgreement = "user_agreement" // UI: terms
	LegalDocTypePrivacyPolicy = "privacy_policy" // UI: privacy
)

// legal version status values. Scheduled is stored as-is; the ACTIVE row is
// derived at read time (the latest version whose effective_at <= now), so a
// scheduled version becomes active automatically without a cron job.
const (
	LegalVersionStatusActive    = "active"
	LegalVersionStatusScheduled = "scheduled"
	LegalVersionStatusRetired   = "retired"
)

// MaxLegalDocBytes limits one archived content snapshot's size.
const MaxLegalDocBytes = 256 * 1024

// OrganizationLegalDocVersion is one immutable published version of a legal
// document for an organization.
type OrganizationLegalDocVersion struct {
	ID             int64  `json:"id" gorm:"primaryKey;autoIncrement"`
	OrganizationID int64  `json:"organization_id" gorm:"column:organization_id;not null;uniqueIndex:uk_org_doc_ver,priority:1;index"`
	// DocType is "user_agreement" / "privacy_policy".
	DocType string `json:"doc_type" gorm:"column:doc_type;type:varchar(32);not null;uniqueIndex:uk_org_doc_ver,priority:2"`
	// Version is monotonic per (organization_id, doc_type), assigned by the
	// backend at publish time.
	Version int64  `json:"version" gorm:"column:version;not null;uniqueIndex:uk_org_doc_ver,priority:3"`
	// URL is the public link shown when users are asked to accept the document.
	URL string `json:"url" gorm:"column:url;type:varchar(512);not null"`
	// Changelog describes what changed in this version (shown in history).
	Changelog string `json:"changelog" gorm:"column:changelog;type:varchar(512)"`
	// Status is "active" / "scheduled" / "retired" as stored at publish time.
	// The effective active row is derived: latest version with effective_at <= now.
	Status string `json:"status" gorm:"column:status;type:varchar(16);not null;index"`
	// EffectiveAt (unix seconds) is when this version becomes/became effective.
	EffectiveAt int64 `json:"effective_at" gorm:"column:effective_at;not null;index"`
	// PublishedBy is the admin display identifier taken from the token context.
	PublishedBy string `json:"published_by" gorm:"column:published_by;type:varchar(255)"`
	PublishedAt int64  `json:"published_at" gorm:"column:published_at;not null"`
	// ContentHash (hex) of the archived snapshot — compliance evidence.
	ContentHash string `json:"content_hash" gorm:"column:content_hash;type:varchar(64)"`
	// HasSnapshot reports whether an immutable content copy was archived.
	HasSnapshot bool `json:"has_snapshot" gorm:"column:has_snapshot;not null;default:0"`
	// Content is the archived snapshot itself (empty when HasSnapshot=false).
	Content string `json:"content" gorm:"column:content;type:mediumtext"`
	CreatedAt int64 `json:"created_at" gorm:"column:created_at;not null"`
}

// TableName defines the table name for the OrganizationLegalDocVersion struct.
func (OrganizationLegalDocVersion) TableName() string {
	return constants.OrganizationLegalDocVersionTableName
}

// OrganizationLegalDocVersionDAO is the data-access handle for legal versions.
type OrganizationLegalDocVersionDAO struct {
	db *gorm.DB
}

// NewOrganizationLegalDocVersionDAO builds a DAO bound to the given connection.
func NewOrganizationLegalDocVersionDAO(db *gorm.DB) *OrganizationLegalDocVersionDAO {
	return &OrganizationLegalDocVersionDAO{db: db}
}

// WithTx returns a DAO that runs its queries on the given transaction.
func (d *OrganizationLegalDocVersionDAO) WithTx(tx *gorm.DB) *OrganizationLegalDocVersionDAO {
	return &OrganizationLegalDocVersionDAO{db: tx}
}

// NextVersion returns the next monotonic version number for (org, docType).
// Called inside the publish transaction; a fresh doc starts at 1.
func (d *OrganizationLegalDocVersionDAO) NextVersion(organizationID int64, docType string) (int64, error) {
	var maxVersion int64
	err := d.db.Model(&OrganizationLegalDocVersion{}).
		Where("organization_id = ? AND doc_type = ?", organizationID, docType).
		Select("COALESCE(MAX(version), 0)").Scan(&maxVersion).Error
	return maxVersion + 1, err
}

// PublishVersion inserts one immutable version row. The caller must have
// derived version + status (active/scheduled) already.
func (d *OrganizationLegalDocVersionDAO) PublishVersion(v *OrganizationLegalDocVersion) error {
	return d.db.Create(v).Error
}

// RetireActiveVersions marks every currently-active row of (org, docType) as
// retired. MUST be called BEFORE PublishVersion within the same transaction —
// running it after the insert would retire the newly-published row too
// (it is already active), leaving the document with no active version.
func (d *OrganizationLegalDocVersionDAO) RetireActiveVersions(organizationID int64, docType string) error {
	return d.db.Model(&OrganizationLegalDocVersion{}).
		Where("organization_id = ? AND doc_type = ? AND status = ?",
			organizationID, docType, LegalVersionStatusActive).
		Update("status", LegalVersionStatusRetired).Error
}

// ListVersions returns an organization's full immutable version history for
// one doc type, newest first.
func (d *OrganizationLegalDocVersionDAO) ListVersions(organizationID int64, docType string) ([]*OrganizationLegalDocVersion, error) {
	var versions []*OrganizationLegalDocVersion
	if err := d.db.Where("organization_id = ? AND doc_type = ?", organizationID, docType).
		Order("version DESC").Find(&versions).Error; err != nil {
		return nil, err
	}
	return versions, nil
}

// ListAllVersions returns every version row of an organization across doc
// types (the admin list view merges both documents).
func (d *OrganizationLegalDocVersionDAO) ListAllVersions(organizationID int64) ([]*OrganizationLegalDocVersion, error) {
	var versions []*OrganizationLegalDocVersion
	if err := d.db.Where("organization_id = ?", organizationID).
		Order("doc_type asc, version DESC").Find(&versions).Error; err != nil {
		return nil, err
	}
	return versions, nil
}

// GetActiveVersion returns the version that is effective NOW for (org,
// docType): the highest version with effective_at <= now. Falls back to the
// newest scheduled version when nothing is effective yet (better than 404 on a
// fresh org). Returns ErrLegalDocNotExist when the org never published one.
func (d *OrganizationLegalDocVersionDAO) GetActiveVersion(organizationID int64, docType string, now int64) (*OrganizationLegalDocVersion, error) {
	var v OrganizationLegalDocVersion
	err := d.db.Where(
		"organization_id = ? AND doc_type = ? AND effective_at <= ?",
		organizationID, docType, now,
	).Order("version DESC").First(&v).Error
	if err == nil {
		return &v, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	// Nothing effective yet — surface the earliest scheduled version if any.
	var scheduled OrganizationLegalDocVersion
	if err := d.db.Where(
		"organization_id = ? AND doc_type = ?",
		organizationID, docType,
	).Order("effective_at asc").First(&scheduled).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrLegalDocNotExist
		}
		return nil, err
	}
	return &scheduled, nil
}

// GetVersionByNumber returns one exact version row (audit / deep-link reads).
func (d *OrganizationLegalDocVersionDAO) GetVersionByNumber(organizationID int64, docType string, version int64) (*OrganizationLegalDocVersion, error) {
	var v OrganizationLegalDocVersion
	if err := d.db.Where(
		"organization_id = ? AND doc_type = ? AND version = ?",
		organizationID, docType, version,
	).First(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrLegalDocNotExist
		}
		return nil, err
	}
	return &v, nil
}
