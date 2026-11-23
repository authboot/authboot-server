package db

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"
)

var ErrSecurityGrant = errors.New("security grant invalid or expired")

// SecurityGrant stores only a token hash. All selectors must be supplied by the
// authenticated server context when consuming, never trusted from request JSON.
type SecurityGrant struct {
	Hash           string `gorm:"primaryKey;size:64" json:"-"`
	Subject        string `gorm:"size:8;not null" json:"-"`
	AccountID      int64  `gorm:"not null" json:"-"`
	OrganizationID int64  `gorm:"not null" json:"-"`
	SessionID      string `gorm:"size:64;not null" json:"-"`
	Scope          string `gorm:"size:128;not null" json:"-"`
	ExpiresAt      int64  `gorm:"index;not null" json:"-"`
}

func (SecurityGrant) TableName() string { return "tb_security_grants" }

func securityGrantHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func NewSecurityGrant(conn *gorm.DB, binding SecurityGrant, now time.Time, ttl time.Duration) (string, error) {
	if (binding.Subject != "admin" && binding.Subject != "user") || binding.AccountID <= 0 ||
		binding.SessionID == "" || binding.Scope == "" || len(binding.Scope) > 128 ||
		ttl < time.Second || ttl > 5*time.Minute || (binding.Subject == "user" && binding.OrganizationID <= 0) {
		return "", ErrSecurityGrant
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	binding.Hash = securityGrantHash(token)
	binding.ExpiresAt = now.Add(ttl).Unix()
	if err := conn.Create(&binding).Error; err != nil {
		return "", err
	}
	return token, nil
}

// ConsumeSecurityGrant is one conditional DELETE, preventing concurrent replay
// and retaining valid tokens when any authorization binding does not match.
func ConsumeSecurityGrant(conn *gorm.DB, token string, binding SecurityGrant, now time.Time) error {
	if len(token) != 43 || binding.AccountID <= 0 || binding.SessionID == "" || binding.Scope == "" {
		return ErrSecurityGrant
	}
	result := conn.Where(
		"hash = ? AND subject = ? AND account_id = ? AND organization_id = ? AND session_id = ? AND scope = ? AND expires_at > ?",
		securityGrantHash(token), binding.Subject, binding.AccountID, binding.OrganizationID, binding.SessionID, binding.Scope, now.Unix(),
	).Delete(&SecurityGrant{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrSecurityGrant
	}
	return nil
}
