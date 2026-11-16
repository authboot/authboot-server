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

package provider

import (
	"context"
	"fmt"
)

// Token is a provider-agnostic OAuth2 token obtained after exchanging an
// authorization code. Fields that a given vendor does not return are left zero.
type Token struct {
	// AccessToken is used to call the provider's userinfo endpoint.
	AccessToken string
	// RefreshToken refreshes an expired AccessToken, when the vendor supports it.
	RefreshToken string
	// ExpiresIn is the AccessToken lifetime in seconds.
	ExpiresIn int64
	// OpenID is the user id scoped to the current app (returned by WeChat
	// alongside the token); other vendors may leave it empty.
	OpenID string
	// Scope is the space/comma separated list of granted scopes.
	Scope string
}

// UserInfo is a provider-agnostic identity profile, so business code never
// depends on a concrete vendor's payload shape.
type UserInfo struct {
	// Provider is the identity provider id, e.g. "wechat".
	Provider string
	// OpenID uniquely identifies the user within a single app.
	OpenID string
	// UnionID uniquely identifies the user across all apps of the same vendor
	// account (WeChat 开放平台). Empty when the vendor has no such concept.
	UnionID string
	// Nickname is the display name, when available.
	Nickname string
	// AvatarURL is the profile picture URL, when available.
	AvatarURL string
	// Raw carries the decoded vendor payload for fields not modeled above.
	Raw map[string]any
}

// Provider is the identity-provider adapter interface, modeling the OAuth2
// authorization-code flow. To plug in a new vendor (GitHub, Google, 支付宝,
// ...), implement this interface and register it in the oauth facade's Init.
type Provider interface {
	// Name returns the provider identifier, used as the registry key and for
	// logging, e.g. "wechat".
	Name() string
	// AuthCodeURL builds the vendor consent-page URL the caller redirects the
	// end user to. state is an opaque anti-CSRF token echoed back on callback.
	AuthCodeURL(state string) string
	// Exchange swaps the authorization code returned on callback for a Token.
	// Implementations should honor ctx for cancellation / timeout.
	Exchange(ctx context.Context, code string) (*Token, error)
	// UserInfo fetches the end-user profile using a Token from Exchange.
	UserInfo(ctx context.Context, tok *Token) (*UserInfo, error)
}

// validateCode checks the authorization code shared by every provider.
func validateCode(code string) error {
	if code == "" {
		return fmt.Errorf("oauth: authorization code is empty")
	}
	return nil
}
