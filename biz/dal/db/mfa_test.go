package db

import (
	"encoding/base64"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/authboot/authboot-server/pkg/utils"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestMFAAtomicConsumption(t *testing.T) {
	conn, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := conn.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := conn.AutoMigrate(&AdminMFA{}, &AdminMFARecovery{}); err != nil {
		t.Fatal(err)
	}
	cipher, err := utils.NewMFASecretCipher(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("t", 32))))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := utils.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Seal(secret, MFABinding(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Create(&AdminMFA{AccountID: 1, Secret: encrypted, Enabled: true, LastCounter: -1, Generation: 1}).Error; err != nil {
		t.Fatal(err)
	}
	var codes []string
	if err := conn.Transaction(func(tx *gorm.DB) error {
		var err error
		codes, err = ReplaceAdminMFARecovery(tx, 1)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	const now = int64(1234567890)
	totp, _ := utils.TOTP(secret, now, 6)
	for _, proof := range []struct {
		code     string
		recovery bool
	}{{totp, false}, {codes[0], true}} {
		var accepted atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ConsumeAdminMFA(conn, cipher, 1, proof.code, proof.recovery, now) == nil {
					accepted.Add(1)
				}
			}()
		}
		wg.Wait()
		if accepted.Load() != 1 {
			t.Fatalf("accepted %d concurrent proofs", accepted.Load())
		}
	}
	if err := ConsumeAdminMFA(conn, cipher, 2, codes[1], true, now); err == nil {
		t.Fatal("foreign code accepted")
	}
	if err := conn.Model(&AdminMFA{}).Where("account_id = ?", 1).Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	if err := ConsumeAdminMFA(conn, cipher, 1, codes[1], true, now); err == nil {
		t.Fatal("disabled MFA accepted")
	}
}
