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

package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

// envConfigKey names the env var holding the AES-256 key (base64-encoded 32
// bytes) used to encrypt provider config blobs at rest. It is read lazily so
// the package imports cleanly even when oauth is unused.
const envConfigKey = "OAUTH_CONFIG_KEY"

// loadKey decodes the 32-byte AES key from env. It fails closed: without a
// configured key, encryption/decryption is refused rather than silently
// falling back to plaintext.
func loadKey() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv(envConfigKey))
	if raw == "" {
		return nil, fmt.Errorf("oauth: %s is not set; cannot encrypt/decrypt provider config", envConfigKey)
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("oauth: %s must be base64-encoded: %w", envConfigKey, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("oauth: %s must decode to 32 bytes (AES-256), got %d", envConfigKey, len(key))
	}
	return key, nil
}

func newGCM() (cipher.AEAD, error) {
	key, err := loadKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("oauth: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("oauth: new gcm: %w", err)
	}
	return gcm, nil
}

// Encrypt seals plaintext (a vendor's JSON config) for storage in the
// oauth_configs.config column. The admin/config write path uses this before
// calling db.UpsertOAuthConfig. The nonce is prepended to the ciphertext.
func Encrypt(plaintext []byte) ([]byte, error) {
	gcm, err := newGCM()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("oauth: read nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt reverses Encrypt, recovering the vendor JSON from a stored blob.
func decrypt(ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM()
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, fmt.Errorf("oauth: ciphertext too short")
	}
	nonce, body := ciphertext[:ns], ciphertext[ns:]
	plain, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, fmt.Errorf("oauth: decrypt config: %w", err)
	}
	return plain, nil
}

// Decrypt opens a config blob previously sealed by Encrypt. Exposed so the
// admin config read path can render stored settings.
func Decrypt(ciphertext []byte) ([]byte, error) {
	return decrypt(ciphertext)
}
