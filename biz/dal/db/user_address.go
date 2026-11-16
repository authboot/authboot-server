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

// MaxUserAddresses is the per-user cap on saved shipping addresses.
const MaxUserAddresses = 10

// UserAddress is one shipping address in an Organization User's address book.
// It is scoped to (organization_id, user_id); exactly one row per user may have
// IsDefault = true.
type UserAddress struct {
	ID             int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	OrganizationID int64     `json:"organization_id" gorm:"column:organization_id;not null;index"`
	UserID         int64     `json:"user_id" gorm:"column:user_id;not null;index"`
	ReceiverName   string    `json:"receiver_name" gorm:"type:varchar(64)"`
	ReceiverPhone  string    `json:"receiver_phone" gorm:"type:varchar(32)"`
	Province       string    `json:"province" gorm:"type:varchar(64)"`
	City           string    `json:"city" gorm:"type:varchar(64)"`
	District       string    `json:"district" gorm:"type:varchar(64)"`
	Detail         string    `json:"detail" gorm:"type:varchar(255)"`
	IsDefault      bool      `json:"is_default" gorm:"column:is_default;not null;default:0;index"`
	CreatedAt      time.Time `json:"created_at" gorm:"not null"`
	UpdatedAt      time.Time `json:"updated_at" gorm:"not null"`
}

// TableName set table name to make gorm can correctly identify
func (UserAddress) TableName() string { return constants.UserAddressTableName }

// PLACEHOLDER_ADDR

// ListUserAddresses returns a user's addresses, default first then newest.
func ListUserAddresses(userID int64) ([]*UserAddress, error) {
	var addrs []*UserAddress
	if err := DB.Where("user_id = ?", userID).
		Order("is_default DESC, id DESC").Find(&addrs).Error; err != nil {
		return nil, err
	}
	return addrs, nil
}

// ListUserAddressesInOrg returns a user's addresses scoped to an organization,
// default first then newest. This is the admin-side lookup: it filters by both
// organization_id and user_id so an admin of one organization cannot read the
// addresses of a user that belongs to another organization.
func ListUserAddressesInOrg(organizationID, userID int64) ([]*UserAddress, error) {
	var addrs []*UserAddress
	if err := DB.Where("organization_id = ? AND user_id = ?", organizationID, userID).
		Order("is_default DESC, id DESC").Find(&addrs).Error; err != nil {
		return nil, err
	}
	return addrs, nil
}

// CreateUserAddress adds an address, enforcing the per-user cap. The first
// address a user adds becomes the default; otherwise, if the new address is
// flagged default, any previous default is cleared. Runs in a transaction.
func CreateUserAddress(addr *UserAddress) error {
	return DB.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&UserAddress{}).Where("user_id = ?", addr.UserID).Count(&count).Error; err != nil {
			return err
		}
		if count >= MaxUserAddresses {
			return errno.UserAddressLimitErr
		}
		if count == 0 {
			addr.IsDefault = true // first address is default
		} else if addr.IsDefault {
			if err := clearDefault(tx, addr.UserID); err != nil {
				return err
			}
		}
		return tx.Create(addr).Error
	})
}

// UpdateUserAddress updates a user's address by id (ownership enforced via
// user_id). When IsDefault is set true, any other default is cleared.
func UpdateUserAddress(addr *UserAddress) error {
	return DB.Transaction(func(tx *gorm.DB) error {
		var existing UserAddress
		if err := tx.Where("id = ? AND user_id = ?", addr.ID, addr.UserID).First(&existing).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return errno.UserAddressNotExistErr
			}
			return err
		}
		if addr.IsDefault {
			if err := clearDefault(tx, addr.UserID); err != nil {
				return err
			}
		}
		return tx.Model(&UserAddress{}).Where("id = ? AND user_id = ?", addr.ID, addr.UserID).
			Updates(map[string]interface{}{
				"receiver_name":  addr.ReceiverName,
				"receiver_phone": addr.ReceiverPhone,
				"province":       addr.Province,
				"city":           addr.City,
				"district":       addr.District,
				"detail":         addr.Detail,
				"is_default":     addr.IsDefault,
			}).Error
	})
}

// SetDefaultUserAddress marks one of a user's addresses as the default and
// clears the flag on the others. Runs in a transaction.
func SetDefaultUserAddress(userID, addressID int64) error {
	return DB.Transaction(func(tx *gorm.DB) error {
		var existing UserAddress
		if err := tx.Where("id = ? AND user_id = ?", addressID, userID).First(&existing).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return errno.UserAddressNotExistErr
			}
			return err
		}
		if err := clearDefault(tx, userID); err != nil {
			return err
		}
		return tx.Model(&UserAddress{}).Where("id = ? AND user_id = ?", addressID, userID).
			Update("is_default", true).Error
	})
}

// DeleteUserAddress removes a user's address. If the deleted address was the
// default and others remain, the newest remaining address is promoted to
// default so the user always has one. Runs in a transaction.
func DeleteUserAddress(userID, addressID int64) error {
	return DB.Transaction(func(tx *gorm.DB) error {
		var existing UserAddress
		if err := tx.Where("id = ? AND user_id = ?", addressID, userID).First(&existing).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return errno.UserAddressNotExistErr
			}
			return err
		}
		if err := tx.Where("id = ? AND user_id = ?", addressID, userID).Delete(&UserAddress{}).Error; err != nil {
			return err
		}
		if !existing.IsDefault {
			return nil
		}
		var next UserAddress
		if err := tx.Where("user_id = ?", userID).Order("id DESC").First(&next).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil // no addresses left
			}
			return err
		}
		return tx.Model(&UserAddress{}).Where("id = ?", next.ID).Update("is_default", true).Error
	})
}

// clearDefault unsets the default flag on all of a user's addresses.
func clearDefault(tx *gorm.DB, userID int64) error {
	return tx.Model(&UserAddress{}).Where("user_id = ? AND is_default = ?", userID, true).
		Update("is_default", false).Error
}
