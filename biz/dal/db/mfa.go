package db

import (
	"errors"
	"fmt"

	"github.com/authboot/authboot-server/pkg/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AdminMFA is never serialized into an account response.
type AdminMFA struct {
	AccountID      int64  `gorm:"primaryKey;autoIncrement:false" json:"-"`
	Secret         string `gorm:"type:text;not null" json:"-"`
	Enabled        bool   `gorm:"not null" json:"-"`
	LastCounter    int64  `gorm:"not null;default:-1" json:"-"`
	SetupExpiresAt int64  `gorm:"not null" json:"-"`
	Generation     int64  `gorm:"not null" json:"-"`
}

func (AdminMFA) TableName() string { return "tb_admin_mfa" }

type AdminMFARecovery struct {
	AccountID int64  `gorm:"primaryKey;autoIncrement:false" json:"-"`
	Hash      string `gorm:"primaryKey;size:64" json:"-"`
}

func (AdminMFARecovery) TableName() string { return "tb_admin_mfa_recovery" }

func MFABinding(accountID int64) string { return fmt.Sprintf("admin:%d", accountID) }

func CheckAdminMFAGeneration(accountID, generation int64) error {
	u, err := QueryAdminUserByID(accountID)
	if err != nil {
		return err
	}
	if u.MFAGeneration != generation {
		return utils.ErrMFAProof
	}
	return nil
}

// ConsumeAdminMFA serializes TOTP/recovery use with enable/disable/rotation.
// Rate limiting must be applied before calling this function.
func ConsumeAdminMFA(conn *gorm.DB, cipher *utils.MFASecretCipher, accountID int64, code string, recovery bool, now int64) error {
	if accountID <= 0 || code == "" {
		return utils.ErrMFAProof
	}
	return conn.Transaction(func(tx *gorm.DB) error {
		var state AdminMFA
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("account_id = ?", accountID).First(&state).Error; err != nil {
			return err
		}
		if !state.Enabled {
			return utils.ErrMFAProof
		}
		if recovery {
			result := tx.Where("account_id = ? AND hash = ?", accountID, utils.MFARecoveryHash(MFABinding(accountID), code)).Delete(&AdminMFARecovery{})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return utils.ErrMFAProof
			}
			return nil
		}
		secret, err := cipher.Open(state.Secret, MFABinding(accountID))
		if err != nil {
			return err
		}
		counter, err := utils.MatchTOTP(secret, code, now, state.LastCounter)
		if err != nil {
			return err
		}
		result := tx.Model(&AdminMFA{}).Where("account_id = ? AND enabled = ? AND generation = ? AND last_counter < ?", accountID, true, state.Generation, counter).Update("last_counter", counter)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return utils.ErrMFAProof
		}
		return nil
	})
}

// ReplaceAdminMFARecovery must share the caller's transaction/locked MFA row.
// Plaintext codes are returned once and never stored.
func ReplaceAdminMFARecovery(tx *gorm.DB, accountID int64) ([]string, error) {
	if accountID <= 0 {
		return nil, errors.New("invalid MFA account")
	}
	codes := make([]string, 10)
	rows := make([]AdminMFARecovery, len(codes))
	for i := range codes {
		code, err := utils.NewMFARecoveryCode()
		if err != nil {
			return nil, err
		}
		codes[i] = code
		rows[i] = AdminMFARecovery{AccountID: accountID, Hash: utils.MFARecoveryHash(MFABinding(accountID), code)}
	}
	if err := tx.Where("account_id = ?", accountID).Delete(&AdminMFARecovery{}).Error; err != nil {
		return nil, err
	}
	if err := tx.Create(&rows).Error; err != nil {
		return nil, err
	}
	return codes, nil
}
