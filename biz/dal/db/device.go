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
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/geoip"
)

// Device registry: one row per (account, device), upserted on every login and
// touched on session activity. Admin and user devices live in SEPARATE tables
// (mirrors the session tables) so the two identity systems never mix. A device
// row survives session expiry — it answers "which devices has this account ever
// used", while the session tables answer "which sessions are alive now".

// AdminDevice is one platform-admin's registered device.
type AdminDevice struct {
	ID         int64  `json:"id" gorm:"primaryKey;autoIncrement"`
	AccountID  int64  `json:"account_id" gorm:"column:account_id;not null;uniqueIndex:uk_admin_device;index"`
	DeviceID   string `json:"device_id" gorm:"column:device_id;type:varchar(64);not null;uniqueIndex:uk_admin_device"`
	DeviceName string `json:"device_name" gorm:"column:device_name;type:varchar(128)"`
	LastIP     string `json:"last_ip" gorm:"column:last_ip;type:varchar(64)"`
	UserAgent  string `json:"user_agent" gorm:"column:user_agent;type:varchar(255)"`
	LoginCount int64  `json:"login_count" gorm:"column:login_count;not null;default:1"`
	CreatedAt  int64  `json:"created_at" gorm:"column:created_at;not null"`
	LastUsedAt int64  `json:"last_used_at" gorm:"column:last_used_at;not null;index"`
}

// TableName defines the table name for the AdminDevice struct.
func (AdminDevice) TableName() string { return constants.AdminDeviceTableName }

// UserDevice is one App-user's registered device, symmetric to AdminDevice but
// org-scoped (an App user always belongs to one organization).
type UserDevice struct {
	LastActiveAt       int64          `json:"last_active_at" gorm:"not null;default:0"`
	LastActiveIP       string         `json:"last_active_ip" gorm:"type:varchar(64)"`
	LastActiveLocation geoip.Location `json:"last_active_location" gorm:"serializer:json;type:text"`
	LastLocation       geoip.Location `json:"last_location" gorm:"serializer:json;type:text"`
	ID                 int64          `json:"id" gorm:"primaryKey;autoIncrement"`
	OrganizationID     int64          `json:"organization_id" gorm:"column:organization_id;not null;index"`
	UserID             int64          `json:"user_id" gorm:"column:user_id;not null;uniqueIndex:uk_user_device;index"`
	DeviceID           string         `json:"device_id" gorm:"column:device_id;type:varchar(64);not null;uniqueIndex:uk_user_device"`
	DeviceName         string         `json:"device_name" gorm:"column:device_name;type:varchar(128)"`
	ClientID           int64          `json:"client_id" gorm:"column:client_id"`
	LastIP             string         `json:"last_ip" gorm:"column:last_ip;type:varchar(64)"`
	UserAgent          string         `json:"user_agent" gorm:"column:user_agent;type:varchar(255)"`
	LoginCount         int64          `json:"login_count" gorm:"column:login_count;not null;default:1"`
	CreatedAt          int64          `json:"created_at" gorm:"column:created_at;not null"`
	LastUsedAt         int64          `json:"last_used_at" gorm:"column:last_used_at;not null;index"`
}

// TableName defines the table name for the UserDevice struct.
func (UserDevice) TableName() string { return constants.UserDeviceTableName }

// UpsertAdminDevice records a login from an admin device: first sight inserts,
// later logins bump login_count / last_ip / last_used_at.
func UpsertAdminDevice(accountID int64, deviceID, deviceName, ip, userAgent string, now int64) error {
	if deviceID == "" {
		return nil
	}
	return DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "account_id"}, {Name: "device_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"device_name":  deviceName,
			"last_ip":      ip,
			"user_agent":   userAgent,
			"login_count":  gorm.Expr("login_count + 1"),
			"last_used_at": now,
		}),
	}).Create(&AdminDevice{
		AccountID:  accountID,
		DeviceID:   deviceID,
		DeviceName: deviceName,
		LastIP:     ip,
		UserAgent:  userAgent,
		CreatedAt:  now,
		LastUsedAt: now,
	}).Error
}

// UpsertUserDevice records a login from a user device, symmetric to
// UpsertAdminDevice.
func UpsertUserDevice(organizationID, userID, clientID int64, deviceID, deviceName, ip, userAgent string, now int64, location geoip.Location) error {
	if deviceID == "" {
		return nil
	}
	return DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}, {Name: "device_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"last_location": gorm.Expr("VALUES(last_location)"),
			"device_name":   deviceName,
			"client_id":     clientID,
			"last_ip":       ip,
			"user_agent":    userAgent,
			"login_count":   gorm.Expr("login_count + 1"),
			"last_used_at":  now,
		}),
	}).Create(&UserDevice{
		LastLocation:   location,
		OrganizationID: organizationID,
		UserID:         userID,
		DeviceID:       deviceID,
		DeviceName:     deviceName,
		ClientID:       clientID,
		LastIP:         ip,
		UserAgent:      userAgent,
		CreatedAt:      now,
		LastUsedAt:     now,
	}).Error
}

// ListAdminDevices returns an admin's registered devices, most recently used
// first.
func ListAdminDevices(accountID int64) ([]*AdminDevice, error) {
	var rows []*AdminDevice
	err := DB.Where("account_id = ?", accountID).Order("last_used_at DESC").Find(&rows).Error
	return rows, err
}

// ListUserDevices returns a user's registered devices, most recently used first.
func ListUserDevices(organizationID, userID int64) ([]*UserDevice, error) {
	var rows []*UserDevice
	err := DB.Where("organization_id = ? AND user_id = ?", organizationID, userID).
		Order("last_used_at DESC").Find(&rows).Error
	return rows, err
}
