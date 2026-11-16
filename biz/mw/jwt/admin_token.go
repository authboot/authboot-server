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

// AdminClaims is the claim set signed into an INTERNAL platform admin access
// token. AdminID is the Platform Account id. SessionID ties the token to its
// server-side admin session so logout immediately invalidates it.
type AdminClaims struct {
	AdminID        int64  `json:"admin_id"`
	OrganizationID int64  `json:"organization_id"`
	SessionID      string `json:"session_id,omitempty"`
	jwtv4.RegisteredClaims
}

// adminKey returns the HS256 signing key for admin tokens, read from
// JWT_SECRET_KEY_ADMIN. Fails closed (os.Exit) when unset, so admin tokens are
// cryptographically isolated from user tokens.
func adminKey() []byte {
	key := os.Getenv("JWT_SECRET_KEY_ADMIN")
	if key == "" {
		fmt.Fprintf(os.Stderr, "fatal: JWT_SECRET_KEY_ADMIN is not set. Generate one with: openssl rand -base64 32\n")
		os.Exit(1)
	}
	return []byte(key)
}

// GenerateAdminAccessToken issues a short-lived admin access token bound to a
// server-side admin session (sessionID). Pair it with the redis SessionStore
// (SubjectAdmin namespace), which owns the opaque refresh token. ttl is the
// access-token lifetime; pass DefaultAccessTTL() for the platform default, or an
// organization's configured value for org-scoped tokens.
func GenerateAdminAccessToken(adminID, organizationID int64, sessionID string, ttl time.Duration) (accessToken string, accessExpiresAt int64, err error) {
	now := time.Now()
	expiresAt := now.Add(ttl)
	claims := AdminClaims{
		AdminID:        adminID,
		OrganizationID: organizationID,
		SessionID:      sessionID,
		RegisteredClaims: jwtv4.RegisteredClaims{
			IssuedAt:  jwtv4.NewNumericDate(now),
			ExpiresAt: jwtv4.NewNumericDate(expiresAt),
		},
	}
	token := jwtv4.NewWithClaims(jwtv4.SigningMethodHS256, claims)
	signed, err := token.SignedString(adminKey())
	if err != nil {
		return "", 0, err
	}
	return signed, expiresAt.Unix(), nil
}

// ParseAdminToken validates an admin access token's signature and expiry using
// the admin key. A user token (signed with the user key) fails here, enforcing
// the admin/user boundary at the cryptographic layer.
func ParseAdminToken(tokenString string) (*AdminClaims, error) {
	claims := &AdminClaims{}
	token, err := jwtv4.ParseWithClaims(tokenString, claims, func(t *jwtv4.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtv4.SigningMethodHMAC); !ok {
			return nil, errors.New("jwt: unexpected signing method")
		}
		return adminKey(), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("jwt: invalid token")
	}
	return claims, nil
}
