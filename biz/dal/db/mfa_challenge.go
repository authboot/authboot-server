package db

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"gorm.io/gorm"
)

type AdminMFAChallenge struct {
	Hash         string `gorm:"primaryKey;size:64" json:"-"`
	AccountID    int64  `gorm:"not null" json:"-"`
	Generation   int64  `gorm:"not null" json:"-"`
	DeviceID     string `gorm:"size:255" json:"-"`
	DeviceName   string `gorm:"size:255" json:"-"`
	IP           string `gorm:"size:64" json:"-"`
	UserAgent    string `gorm:"type:text" json:"-"`
	PasswordHash string `gorm:"size:255" json:"-"`
	ExpiresAt    int64  `gorm:"index;not null" json:"-"`
	Attempts     int    `gorm:"not null" json:"-"`
}

func (AdminMFAChallenge) TableName() string { return "tb_admin_mfa_challenges" }

func NewAdminMFAChallenge(conn *gorm.DB, row AdminMFAChallenge, now time.Time) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	row.Hash = securityGrantHash(token)
	row.ExpiresAt = now.Add(3 * time.Minute).Unix()
	row.Attempts = 0
	if err := conn.Create(&row).Error; err != nil {
		return "", err
	}
	return token, nil
}

// An attempted verification is persisted before any proof work, including
// invalid proofs. Metadata is fixed at password verification time.
func AttemptAdminMFAChallenge(conn *gorm.DB, token, ip, ua string, now time.Time) (*AdminMFAChallenge, error) {
	if len(token) != 43 {
		return nil, ErrSecurityGrant
	}
	hash := securityGrantHash(token)
	result := conn.Model(&AdminMFAChallenge{}).Where("hash = ? AND ip = ? AND user_agent = ? AND expires_at > ? AND attempts < 5", hash, ip, ua, now.Unix()).Update("attempts", gorm.Expr("attempts + 1"))
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected != 1 {
		return nil, ErrSecurityGrant
	}
	var row AdminMFAChallenge
	if err := conn.Where("hash = ?", hash).First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func ConsumeAdminMFAChallenge(tx *gorm.DB, row *AdminMFAChallenge, now time.Time) error {
	result := tx.Where("hash = ? AND expires_at > ?", row.Hash, now.Unix()).Delete(&AdminMFAChallenge{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrSecurityGrant
	}
	return nil
}
