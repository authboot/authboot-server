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

// EmailTemplate is one organization's override of a system email template
// (verification_code / invitation / security_alert). Absence of a row means
// the built-in default is used. Subject and Body use Go html/template syntax
// and are validated by the service before being written.
type EmailTemplate struct {
	ID             int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	OrganizationID int64     `json:"organization_id" gorm:"column:organization_id;not null;uniqueIndex:uk_org_template,priority:1"`
	TemplateID     string    `json:"template_id" gorm:"column:template_id;type:varchar(32);not null;uniqueIndex:uk_org_template,priority:2"`
	Subject        string    `json:"subject" gorm:"column:subject;type:varchar(255);not null"`
	Body           string    `json:"body" gorm:"column:body;type:text;not null"`
	CreatedAt      time.Time `json:"created_at" gorm:"not null"`
	UpdatedAt      time.Time `json:"updated_at" gorm:"not null"`
}

func (EmailTemplate) TableName() string {
	return constants.EmailTemplateTableName
}

// EmailTemplateDAO is the data-access handle for the table.
type EmailTemplateDAO struct {
	db *gorm.DB
}

// NewEmailTemplateDAO builds a DAO bound to the given connection.
func NewEmailTemplateDAO(db *gorm.DB) *EmailTemplateDAO {
	return &EmailTemplateDAO{db: db}
}

// WithTx returns a DAO that runs its queries on the given transaction.
func (d *EmailTemplateDAO) WithTx(tx *gorm.DB) *EmailTemplateDAO {
	return &EmailTemplateDAO{db: tx}
}

// Query returns the override for (organizationID, templateID). Missing
// surfaces gorm.ErrRecordNotFound so callers can fall back to the default.
func (d *EmailTemplateDAO) Query(organizationID int64, templateID string) (*EmailTemplate, error) {
	var row EmailTemplate
	if err := d.db.Where("organization_id = ? AND template_id = ?", organizationID, templateID).
		First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// List returns every override of an organization.
func (d *EmailTemplateDAO) List(organizationID int64) ([]*EmailTemplate, error) {
	var rows []*EmailTemplate
	if err := d.db.Where("organization_id = ?", organizationID).
		Order("template_id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// Upsert inserts or updates the override keyed by the unique index.
func (d *EmailTemplateDAO) Upsert(row *EmailTemplate) error {
	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "organization_id"}, {Name: "template_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"subject", "body", "updated_at"}),
	}).Create(row).Error
}

// Delete removes an override so the built-in default applies again.
func (d *EmailTemplateDAO) Delete(organizationID int64, templateID string) error {
	return d.db.Where("organization_id = ? AND template_id = ?", organizationID, templateID).
		Delete(&EmailTemplate{}).Error
}
