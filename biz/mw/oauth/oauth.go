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
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/authboot/authboot-server/biz/mw/oauth/provider"
)

// Provider, Token and UserInfo are re-exported from the provider package so
// callers can use oauth.Provider / oauth.UserInfo without importing the subpackage.
type (
	Provider = provider.Provider
	Token    = provider.Token
	UserInfo = provider.UserInfo
)

// Multi-tenant OAuth: unlike the previous single process-wide config read from
// env, each organization has its own credentials per provider. Configs live in
// a ConfigStore (keyed by org + provider) and Providers are built lazily and
// cached by (orgID, provider).
var (
	store ConfigStore

	mu    sync.RWMutex
	cache = map[string]Provider{} // key: orgID:provider
)

// Init wires the ConfigStore used to resolve per-organization provider configs.
// Call once at startup, e.g. oauth.Init(oauth.NewDBStore()).
func Init(s ConfigStore) { store = s }

func cacheKey(orgID int64, name string) string {
	return fmt.Sprintf("%d:%s", orgID, name)
}

// getFor resolves the Provider for (orgID, name), building it from the store on
// first use and caching the result. Config edits must call Invalidate so the
// next lookup rebuilds with fresh credentials.
func getFor(ctx context.Context, orgID int64, name string) (Provider, error) {
	if store == nil {
		return nil, fmt.Errorf("oauth: not initialized, call oauth.Init(store) at startup")
	}

	key := cacheKey(orgID, name)
	mu.RLock()
	if p, ok := cache[key]; ok {
		mu.RUnlock()
		return p, nil
	}
	mu.RUnlock()

	p, err := buildProvider(ctx, orgID, name)
	if err != nil {
		return nil, err
	}

	mu.Lock()
	cache[key] = p
	mu.Unlock()
	return p, nil
}

// buildProvider loads the org's config for name and constructs the concrete
// Provider. Add a case here to support a new vendor (alipay, github, ...).
func buildProvider(ctx context.Context, orgID int64, name string) (Provider, error) {
	raw, err := store.Load(ctx, orgID, name)
	if err != nil {
		return nil, err
	}
	return buildProviderFromConfig(name, raw)
}

// buildProviderFromConfig constructs a Provider from a plaintext config blob.
func buildProviderFromConfig(name string, raw []byte) (Provider, error) {
	switch name {
	case "wechat":
		var cfg provider.WechatConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("oauth: decode wechat config: %w", err)
		}
		return provider.NewWechatProvider(cfg), nil
	default:
		return nil, fmt.Errorf("oauth: unsupported provider %q", name)
	}
}

// AuthCodeURLWithRedirect is AuthCodeURL with an optional redirect_uri override
// (the stored config's redirect_uri is used when override is empty). The
// override is applied to the decrypted config blob before the provider is
// built, so vendor-specific URL building stays in the provider.
func AuthCodeURLWithRedirect(ctx context.Context, orgID int64, name, state, override string) (string, error) {
	if override == "" {
		return AuthCodeURL(ctx, orgID, name, state)
	}
	if store == nil {
		return "", fmt.Errorf("oauth: not initialized, call oauth.Init(store) at startup")
	}
	raw, err := store.Load(ctx, orgID, name)
	if err != nil {
		return "", err
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", fmt.Errorf("oauth: decode config for redirect override: %w", err)
	}
	cfg["redirect_uri"] = override
	patched, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	p, err := buildProviderFromConfig(name, patched)
	if err != nil {
		return "", err
	}
	return p.AuthCodeURL(state), nil
}

// Invalidate drops the cached Provider for (orgID, name) so the next call
// rebuilds it from the store. Call this after updating an org's config.
func Invalidate(orgID int64, name string) {
	mu.Lock()
	delete(cache, cacheKey(orgID, name))
	mu.Unlock()
}

// InvalidateOrg drops every cached Provider for an organization.
func InvalidateOrg(orgID int64) {
	prefix := fmt.Sprintf("%d:", orgID)
	mu.Lock()
	for k := range cache {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(cache, k)
		}
	}
	mu.Unlock()
}

// AuthCodeURL builds the consent-page URL for an org's named provider.
func AuthCodeURL(ctx context.Context, orgID int64, name, state string) (string, error) {
	p, err := getFor(ctx, orgID, name)
	if err != nil {
		return "", err
	}
	return p.AuthCodeURL(state), nil
}

// Exchange swaps an authorization code for a Token via an org's named provider.
func Exchange(ctx context.Context, orgID int64, name, code string) (*Token, error) {
	p, err := getFor(ctx, orgID, name)
	if err != nil {
		return nil, err
	}
	return p.Exchange(ctx, code)
}

// FetchUserInfo fetches the end-user profile via an org's named provider.
func FetchUserInfo(ctx context.Context, orgID int64, name string, tok *Token) (*UserInfo, error) {
	p, err := getFor(ctx, orgID, name)
	if err != nil {
		return nil, err
	}
	return p.UserInfo(ctx, tok)
}
