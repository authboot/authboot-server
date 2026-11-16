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

	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
)

const organizationTableName = "tb_organization"

type Organization struct {
	ID   int64  `json:"id" gorm:"primaryKey;autoIncrement"`
	Name string `json:"name" gorm:"type:varchar(128);not null"`
	Code string `json:"code" gorm:"type:varchar(64);not null;uniqueIndex"`
	Logo string `json:"logo" gorm:"type:varchar(512)"`
	// PreviousLogo 记录最近一次被替换掉的旧 logo（"bucket/key" 相对路径），仅保留最新一条
	PreviousLogo string    `json:"previous_logo" gorm:"type:varchar(512)"`
	// Settings 组织级配置（admin token 时长、用户登录方式等），JSON 存储，见
	// OrganizationSettings；空串表示全部使用默认值
	Settings     string    `json:"settings" gorm:"type:json"`
	Status       int8      `json:"status" gorm:"type:tinyint;not null;default:1;index"`
	CreatedAt   time.Time `json:"created_at" gorm:"not null"`
	UpdatedAt   time.Time `json:"updated_at" gorm:"not null"`
}

// TableName set table name to make gorm can correctly identify
func (Organization) TableName() string {
	return organizationTableName
}

// OrganizationDAO is the data-access handle for the organization table. It
// wraps a *gorm.DB so the same methods run on the global connection (via the
// package default instance Organizations) or inside a transaction (via WithTx).
type OrganizationDAO struct {
	db *gorm.DB
}

// NewOrganizationDAO builds an OrganizationDAO bound to the given connection.
func NewOrganizationDAO(db *gorm.DB) *OrganizationDAO {
	return &OrganizationDAO{db: db}
}

// WithTx returns an OrganizationDAO that runs its queries on the given transaction.
func (d *OrganizationDAO) WithTx(tx *gorm.DB) *OrganizationDAO {
	return &OrganizationDAO{db: tx}
}

func (d *OrganizationDAO) CreateOrganization(org *Organization) (int64, error) {
	var existing Organization
	if err := d.db.Where("code = ?", org.Code).Find(&existing).Error; err != nil {
		return 0, err
	}
	if existing.ID != 0 {
		return 0, errno.OrganizationAlreadyExistErr
	}
	if org.Status == 0 {
		org.Status = constants.StatusEnabled
	}
	if err := d.db.Create(org).Error; err != nil {
		return 0, err
	}
	return org.ID, nil
}

func (d *OrganizationDAO) QueryOrganizationByID(id int64) (*Organization, error) {
	var org Organization
	if err := d.db.Where("id = ?", id).Find(&org).Error; err != nil {
		return nil, err
	}
	if org.ID == 0 {
		return nil, errno.OrganizationNotExistErr
	}
	return &org, nil
}

func (d *OrganizationDAO) QueryOrganizationByCode(code string) (*Organization, error) {
	var org Organization
	if err := d.db.Where("code = ?", code).Find(&org).Error; err != nil {
		return nil, err
	}
	if org.ID == 0 {
		return nil, errno.OrganizationNotExistErr
	}
	return &org, nil
}

func (d *OrganizationDAO) ListOrganizations() ([]*Organization, error) {
	var orgs []*Organization
	if err := d.db.Order("id asc").Find(&orgs).Error; err != nil {
		return nil, err
	}
	return orgs, nil
}

func (d *OrganizationDAO) SetOrganizationStatus(id int64, status int) error {
	return d.db.Model(&Organization{}).Where("id = ?", id).Update("status", status).Error
}

func (d *OrganizationDAO) UpdateOrganization(org *Organization) error {
	return d.db.Model(&Organization{}).Where("id = ?", org.ID).Updates(map[string]interface{}{
		"name":          org.Name,
		"code":          org.Code,
		"logo":          org.Logo,
		"previous_logo": org.PreviousLogo,
		"status":        org.Status,
	}).Error
}

// UpdateOrganizationSettings persists the org's settings JSON blob only,
// leaving the other organization fields untouched.
func (d *OrganizationDAO) UpdateOrganizationSettings(id int64, settingsJSON string) error {
	return d.db.Model(&Organization{}).Where("id = ?", id).Update("settings", settingsJSON).Error
}
