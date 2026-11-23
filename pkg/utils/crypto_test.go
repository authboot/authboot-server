package utils

import (
	"golang.org/x/crypto/bcrypt"
	"strings"
	"testing"
)

func TestPasswordPolicyAndLegacyUpgrade(t *testing.T) {
	for _, password := range []string{"", "short", strings.Repeat("a", 73), strings.Repeat("中", 25)} {
		if _, err := Crypt(password); err == nil {
			t.Fatal("accepted invalid byte length")
		}
	}
	hash, err := Crypt(strings.Repeat("a", 72))
	if err != nil {
		t.Fatal(err)
	}
	cost, _ := bcrypt.Cost([]byte(hash))
	if cost != bcrypt.DefaultCost {
		t.Fatal(cost)
	}
	legacy, _ := bcrypt.GenerateFromPassword([]byte("short"), 5)
	if !VerifyPassword("short", string(legacy)) {
		t.Fatal("legacy login broken")
	}
	if upgraded, _ := UpgradePassword("wrong", string(legacy)); upgraded != "" {
		t.Fatal("upgraded failed authentication")
	}
	upgraded, err := UpgradePassword("short", string(legacy))
	if err != nil || !VerifyPassword("short", upgraded) {
		t.Fatal("upgrade failed", err)
	}
	cost, _ = bcrypt.Cost([]byte(upgraded))
	if cost != bcrypt.DefaultCost {
		t.Fatal(cost)
	}
}
