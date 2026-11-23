package utils

import (
	"encoding/base32"
	"encoding/base64"
	"strings"
	"testing"
)

func TestTOTPRFC6238(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, v := range []struct {
		at   int64
		want string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		got, err := TOTP(secret, v.at, 8)
		if err != nil || got != v.want {
			t.Fatalf("at %d: got %q, err %v", v.at, got, err)
		}
	}
}

func TestTOTPWindowAndReplay(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	const now = int64(1234567890)
	for _, delta := range []int64{-30, 0, 30} {
		code, _ := TOTP(secret, now+delta, 6)
		counter, err := MatchTOTP(secret, code, now, -1)
		if err != nil || counter != (now+delta)/30 {
			t.Fatal("window rejected")
		}
		if _, err := MatchTOTP(secret, code, now, counter); err == nil {
			t.Fatal("replay accepted")
		}
	}
	code, _ := TOTP(secret, now-90, 6)
	if _, err := MatchTOTP(secret, code, now, -1); err == nil {
		t.Fatal("expired proof accepted")
	}
}

func TestMFAEncryption(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	c, err := NewMFASecretCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := c.Seal("secret", "admin:1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Open(encrypted, "admin:1")
	if err != nil || got != "secret" {
		t.Fatal("round trip failed")
	}
	if _, err := c.Open(encrypted, "admin:2"); err == nil {
		t.Fatal("foreign binding accepted")
	}
	other, _ := NewMFASecretCipher(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))))
	if _, err := other.Open(encrypted, "admin:1"); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := NewMFASecretCipher(""); err == nil {
		t.Fatal("missing key accepted")
	}
	if _, err := c.Open("plaintext", "admin:1"); err == nil {
		t.Fatal("plaintext accepted")
	}
	second, _ := c.Seal("secret", "admin:1")
	if second == encrypted {
		t.Fatal("nonce reused")
	}
}

func TestRecoveryAccountBinding(t *testing.T) {
	code, err := NewMFARecoveryCode()
	if err != nil || len(code) != 32 {
		t.Fatal("invalid recovery code")
	}
	if MFARecoveryHash("admin:1", code) == MFARecoveryHash("user:1", code) {
		t.Fatal("domain collision")
	}
}
