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

package utils

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
)

// Crypt Encrypt the password using crypto/bcrypt
func Crypt(password string) (string, error) {
	if !ValidNewPassword(password) {
		return "", errors.New("password must contain 8 to 72 bytes")
	}

	// Hash password with bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashedPassword), err
}

func ValidNewPassword(password string) bool {
	return len(password) >= 8 && len(password) <= 72
}

// VerifyPassword Verify the password is consistent with the hashed password in the database
func VerifyPassword(password, hashedPassword string) bool {
	if len(password) > 72 || password == "" {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false
	}
	return true
}

// UpgradePassword preserves legacy short passwords only after authentication.
// The caller must persist the result with a compare-and-swap of the old hash.
func UpgradePassword(password, hash string) (string, error) {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil || cost >= bcrypt.DefaultCost || !VerifyPassword(password, hash) {
		return "", err
	}
	upgraded, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(upgraded), err
}
