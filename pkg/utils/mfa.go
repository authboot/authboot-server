package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

var ErrMFAProof = errors.New("invalid MFA proof")

// NewTOTPSecret generates a 160-bit RFC 6238 SHA-1 key.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// TOTP implements RFC 6238 with the interoperable SHA-1 algorithm and 30s step.
// Production callers use six digits; eight digits are supported for RFC vectors.
func TOTP(secret string, unix int64, digits int) (string, error) {
	if unix < 0 || (digits != 6 && digits != 8) {
		return "", ErrMFAProof
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) < 20 {
		return "", ErrMFAProof
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(unix/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	n := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1000000)
	if digits == 8 {
		mod = 100000000
	}
	return fmt.Sprintf("%0*d", digits, n%mod), nil
}

// MatchTOTP returns the matched counter. The caller MUST atomically advance a
// persisted counter with WHERE last_counter < matched before accepting a proof.
func MatchTOTP(secret, code string, unix, lastCounter int64) (int64, error) {
	if len(code) != 6 || unix < 30 {
		return 0, ErrMFAProof
	}
	for _, delta := range []int64{0, -1, 1} {
		counter := unix/30 + delta
		if counter <= lastCounter {
			continue
		}
		expected, err := TOTP(secret, counter*30, 6)
		if err != nil {
			return 0, err
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return counter, nil
		}
	}
	return 0, ErrMFAProof
}

// MFASecretCipher uses AES-256-GCM; associated data binds ciphertext to its
// account. The version prefix permits explicit future migration, never fallback.
type MFASecretCipher struct{ aead cipher.AEAD }

func NewMFASecretCipher(encodedKey string) (*MFASecretCipher, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("MFA encryption requires a base64-encoded 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("MFA encryption unavailable")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &MFASecretCipher{aead: aead}, nil
}

func (c *MFASecretCipher) Seal(secret, accountBinding string) (string, error) {
	if c == nil || c.aead == nil || accountBinding == "" {
		return "", errors.New("MFA encryption unavailable")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(secret), []byte(accountBinding))
	return "v1:" + base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (c *MFASecretCipher) Open(encrypted, accountBinding string) (string, error) {
	if c == nil || c.aead == nil || accountBinding == "" || len(encrypted) < 3 || encrypted[:3] != "v1:" {
		return "", errors.New("MFA secret unavailable")
	}
	b, err := base64.RawStdEncoding.DecodeString(encrypted[3:])
	if err != nil || len(b) < c.aead.NonceSize()+c.aead.Overhead() {
		return "", errors.New("MFA secret unavailable")
	}
	plain, err := c.aead.Open(nil, b[:c.aead.NonceSize()], b[c.aead.NonceSize():], []byte(accountBinding))
	if err != nil {
		return "", errors.New("MFA secret unavailable")
	}
	return string(plain), nil
}

// Recovery codes have 160 bits of entropy, so SHA-256 storage does not need a
// slow password KDF. Domain/account binding prevents cross-account reuse.
func NewMFARecoveryCode() (string, error) {
	b := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func MFARecoveryHash(accountBinding, code string) string {
	sum := sha256.Sum256([]byte("authboot:mfa:recovery:v1\x00" + accountBinding + "\x00" + code))
	return hex.EncodeToString(sum[:])
}
