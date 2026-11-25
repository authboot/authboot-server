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

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
)

// AdminUser is a platform account (login identity). It is intentionally
// org-agnostic: an admin may belong to several organizations, and those
// memberships (with per-org roles) live in OrganizationMembership — not here.
// The organization a request acts in comes from the token bound via
// SwitchOrganization, not from the account.
//
// Email is the ONLY login identifier (admins do not log in by phone or
// username). Settings holds arbitrary admin preferences as JSON so new
// preferences need no schema change.
type AdminUser struct {
	ID              int64          `json:"id"`
	Email           string         `json:"email" gorm:"column:email;type:varchar(255);index"`
	UserName        string         `json:"user_name"`
	Password        string         `json:"password"`
	Avatar          string         `json:"avatar"`
	BackgroundImage string         `json:"background_image"`
	Signature       string         `json:"signature"`
	Status          int8           `json:"status" gorm:"column:status;type:tinyint;not null;default:1;index"`
	MFAEnabled      bool           `json:"-" gorm:"not null;default:false"`
	MFAGeneration   int64          `json:"-" gorm:"not null;default:0"`
	Settings        datatypes.JSON `json:"settings" gorm:"column:settings;type:json"`
	CreatedAt       time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt       time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
}

func (AdminUser) TableName() string { return constants.AdminUserTableName }

// QueryAdminUser query User by user_name (legacy global lookup, kept for compatibility).
func QueryAdminUser(email string) (*AdminUser, error) {
	var adminUser AdminUser
	if err := DB.Where("email = ?", email).First(&adminUser).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errno.UserIsNotExistErr
		}

		return nil, err
	}
	return &adminUser, nil
}

// QueryAdminUserByID returns a platform account by id (self-service reads).
func QueryAdminUserByID(id int64) (*AdminUser, error) {
	var adminUser AdminUser
	if err := DB.Where("id = ?", id).First(&adminUser).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errno.UserIsNotExistErr
		}
		return nil, err
	}
	return &adminUser, nil
}

// UpdateAdminUserProfile persists an admin's mutable profile fields.
func UpdateAdminUserProfile(u *AdminUser) error {
	return DB.Model(&AdminUser{}).Where("id = ?", u.ID).
		Updates(map[string]interface{}{
			"user_name":        u.UserName,
			"avatar":           u.Avatar,
			"background_image": u.BackgroundImage,
			"signature":        u.Signature,
		}).Error
}

// UpdateAdminUserAvatar changes only an admin's avatar reference.
func UpdateAdminUserAvatar(id int64, avatar string) error {
	return DB.Model(&AdminUser{}).Where("id = ?", id).
		Update("avatar", avatar).Error
}

// UpdateAdminUserSettings replaces an admin's settings JSON.
func UpdateAdminUserSettings(id int64, settings datatypes.JSON) error {
	return DB.Model(&AdminUser{}).Where("id = ?", id).
		Update("settings", settings).Error
}
