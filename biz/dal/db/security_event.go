package db

import (
	"errors"
	"time"

	"github.com/authboot/authboot-server/pkg/geoip"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserSecurityEvent deliberately has no relationship to admin notifications.
type UserSecurityEvent struct {
	ID             string         `json:"id" gorm:"primaryKey;type:varchar(64)"`
	OrganizationID int64          `json:"organization_id" gorm:"not null;index:idx_security_owner"`
	UserID         int64          `json:"user_id" gorm:"not null;index:idx_security_owner"`
	SessionID      string         `json:"session_id" gorm:"type:varchar(64);uniqueIndex"`
	DeviceID       string         `json:"device_id" gorm:"type:varchar(64)"`
	Kind           string         `json:"kind" gorm:"type:varchar(64)"`
	IP             string         `json:"ip" gorm:"type:varchar(64)"`
	Location       geoip.Location `json:"location" gorm:"serializer:json;type:text"`
	Status         string         `json:"status" gorm:"type:varchar(32)"`
	CreatedAt      int64          `json:"created_at"`
	ResolvedAt     int64          `json:"resolved_at"`
	NotifyStatus   string         `json:"notify_status" gorm:"type:varchar(32);index"`
	NotifyAttempts int            `json:"-" gorm:"not null;default:0"`
	NotifyAfter    int64          `json:"-" gorm:"not null;default:0"`
}

func (UserSecurityEvent) TableName() string { return "tb_user_security_events" }

func CountryChanged(a, b geoip.Location) bool {
	return a.Status == "approximate" && b.Status == "approximate" && a.CountryCode != "" && b.CountryCode != "" && a.CountryCode != b.CountryCode
}

// RecordSecurityLogin serializes same-user logins using the existing user row.
// Device registration and event creation commit together, so repeated logins do
// not generate duplicate first-device events. Client IDs are descriptive only.
func RecordSecurityLogin(device *UserDevice, sid string) (*UserSecurityEvent, error) {
	var event *UserSecurityEvent
	err := DB.Transaction(func(tx *gorm.DB) error {
		var owner User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND organization_id = ?", device.UserID, device.OrganizationID).First(&owner).Error; err != nil {
			return err
		}
		var previous UserDevice
		err := tx.Where("organization_id = ? AND user_id = ?", device.OrganizationID, device.UserID).Order("last_used_at DESC, id DESC").First(&previous).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		changed := err == nil && CountryChanged(previous.LastLocation, device.LastLocation)
		fresh := false
		if device.DeviceID != "" {
			var existing UserDevice
			err = tx.Where("organization_id = ? AND user_id = ? AND device_id = ?", device.OrganizationID, device.UserID, device.DeviceID).First(&existing).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				fresh = true
				if err := tx.Create(device).Error; err != nil {
					return err
				}
			} else if err != nil {
				return err
			} else {
				device.ID, device.CreatedAt, device.LoginCount = existing.ID, existing.CreatedAt, existing.LoginCount+1
				if err := tx.Save(device).Error; err != nil {
					return err
				}
			}
		}
		kind := ""
		if fresh {
			kind = "new_device"
		}
		if changed {
			kind = "country_changed"
		}
		if kind == "" {
			return nil
		}
		event = &UserSecurityEvent{ID: uuid.NewString(), OrganizationID: device.OrganizationID, UserID: device.UserID, SessionID: sid, DeviceID: device.DeviceID, Kind: kind, IP: device.LastIP, Location: device.LastLocation, Status: "pending", CreatedAt: time.Now().Unix(), NotifyStatus: "pending"}
		return tx.Create(event).Error
	})
	return event, err
}
