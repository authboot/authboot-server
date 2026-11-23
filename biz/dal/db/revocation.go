package db

import (
	"time"

	"github.com/authboot/authboot-server/pkg/errno"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RevocationOutbox is committed with the security mutation. Versions, rather
// than wall-clock cutoffs, distinguish new logins even within the same second.
type RevocationOutbox struct {
	ID             uint64 `gorm:"primaryKey"`
	Subject        string `gorm:"size:8;not null"`
	AccountID      int64  `gorm:"not null"`
	OrganizationID int64  `gorm:"not null"`
	BeforeVersion  int64  `gorm:"not null"`
	CreatedAt      int64  `gorm:"autoCreateTime"`
	NextAttemptAt  int64  `gorm:"index:idx_revoke_due,priority:2"`
	LeaseUntil     int64  `gorm:"not null"`
	LeaseToken     string `gorm:"size:64"`
	Attempts       int    `gorm:"not null"`
	CompletedAt    int64  `gorm:"index:idx_revoke_due,priority:1"`
}

func (RevocationOutbox) TableName() string { return "tb_revocation_outbox" }

// MutateUserSecurity locks the account before both the mutation and version
// increment. expectedPassword optionally guards stale credential verification.
func MutateUserSecurity(conn *gorm.DB, org, id int64, expectedPassword *string, changes map[string]any) error {
	return conn.Transaction(func(tx *gorm.DB) error {
		var u User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND organization_id = ?", id, org).First(&u).Error; err != nil {
			return err
		}
		if expectedPassword != nil && u.Password != *expectedPassword {
			return errno.AuthorizationFailedErr
		}
		nextVersion := u.SessionVersion + 1
		changes["session_version"] = nextVersion
		if err := tx.Model(&u).Updates(changes).Error; err != nil {
			return err
		}
		return tx.Create(&RevocationOutbox{Subject: "user", AccountID: id, OrganizationID: org, BeforeVersion: nextVersion, NextAttemptAt: time.Now().Unix()}).Error
	})
}

func CheckUserSessionVersion(org, id, version int64) error {
	var u User
	if err := DB.Where("id = ? AND organization_id = ?", id, org).First(&u).Error; err != nil {
		return err
	}
	if u.SessionVersion != version {
		return errno.AuthorizationFailedErr
	}
	return nil
}
