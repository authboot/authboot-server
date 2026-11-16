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

package jwt

import (
	"errors"
	"fmt"
	"os"
	"time"

	jwtv4 "github.com/golang-jwt/jwt/v4"
)

// UserClaims is the claim set signed into an EXTERNAL org user (customer) access
// token. UserID is the org user id. SessionID ties the token to its server-side
// user session so logout immediately invalidates it.
type UserClaims struct {
	UserID         int64  `json:"user_id"`
	OrganizationID int64  `json:"organization_id"`
	SessionID      string `json:"session_id,omitempty"`
	jwtv4.RegisteredClaims
}

// userKey returns the HS256 signing key for user tokens, read from
// JWT_SECRET_KEY_USER. Fails closed (os.Exit) when unset, so user tokens are
// cryptographically isolated from admin tokens.
func userKey() []byte {
	key := os.Getenv("JWT_SECRET_KEY_USER")
	if key == "" {
		fmt.Fprintf(os.Stderr, "fatal: JWT_SECRET_KEY_USER is not set. Generate one with: openssl rand -base64 32\n")
		os.Exit(1)
	}
	return []byte(key)
}

// GenerateUserAccessToken issues a short-lived user access token bound to a
// server-side user session (sessionID). Pair it with the redis SessionStore
// (SubjectUser namespace), which owns the opaque refresh token.
func GenerateUserAccessToken(userID, organizationID int64, sessionID string) (accessToken string, accessExpiresAt int64, err error) {
	now := time.Now()
	expiresAt := now.Add(appAccessTTL)
	claims := UserClaims{
		UserID:         userID,
		OrganizationID: organizationID,
		SessionID:      sessionID,
		RegisteredClaims: jwtv4.RegisteredClaims{
			IssuedAt:  jwtv4.NewNumericDate(now),
			ExpiresAt: jwtv4.NewNumericDate(expiresAt),
		},
	}
	token := jwtv4.NewWithClaims(jwtv4.SigningMethodHS256, claims)
	signed, err := token.SignedString(userKey())
	if err != nil {
		return "", 0, err
	}
	return signed, expiresAt.Unix(), nil
}

// ParseUserToken validates a user access token's signature and expiry using the
// user key. An admin token (signed with the admin key) fails here, enforcing
// the admin/user boundary at the cryptographic layer.
func ParseUserToken(tokenString string) (*UserClaims, error) {
	claims := &UserClaims{}
	token, err := jwtv4.ParseWithClaims(tokenString, claims, func(t *jwtv4.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtv4.SigningMethodHMAC); !ok {
			return nil, errors.New("jwt: unexpected signing method")
		}
		return userKey(), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("jwt: invalid token")
	}
	return claims, nil
}
