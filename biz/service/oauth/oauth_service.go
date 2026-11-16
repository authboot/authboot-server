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

// Package oauth implements per-organization OAuth provider configuration
// (admin) and the authorize-URL step of the user login flow. The actual code
// exchange + login lives in the auth service, reusing the same login response
// as password / code login.
package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/authboot/authboot-server/biz/dal/db"
	oauthmodel "github.com/authboot/authboot-server/biz/model/oauth"
	oauthmw "github.com/authboot/authboot-server/biz/mw/oauth"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/errno"
)

// oauthStateStore binds the CSRF state returned by the authorize step to a
// short TTL; OAuthLogin consumes it. Reuses the one-time-code store.
var oauthStateStore redis.Code

const (
	// OAuthStateScene namespaces authorize states in the code store.
	OAuthStateScene = "oauth_state"
	// oauthStateTTL is how long an authorize state stays valid.
	oauthStateTTL = 10 * time.Minute
)

// OAuthService manages provider configs and builds authorize URLs.
type OAuthService struct {
	ctx context.Context
	c   *app.RequestContext

	configDAO *db.OAuthConfigDAO
}

// NewOAuthService creates an OAuth configuration service.
func NewOAuthService(ctx context.Context, c *app.RequestContext) *OAuthService {
	return &OAuthService{
		ctx:       ctx,
		c:         c,
		configDAO: db.NewOAuthConfigDAO(db.DB),
	}
}

// SetOAuthConfig upserts an organization's config for a provider. Settings are
// stored as an encrypted JSON blob; the provider cache is invalidated so the
// next login rebuilds with the new credentials.
func (s *OAuthService) SetOAuthConfig(req *oauthmodel.SetOAuthConfigRequest) (*oauthmodel.SetOAuthConfigResponse, error) {
	if req.OrganizationId == 0 || req.Provider == "" {
		return nil, errno.ParamErr
	}
	plain, err := json.Marshal(req.Settings)
	if err != nil {
		return nil, err
	}
	sealed, err := oauthmw.Encrypt(plain)
	if err != nil {
		return nil, err
	}
	enabled := int8(0)
	if req.Enabled {
		enabled = 1
	}
	cfg := &db.OAuthConfig{
		OrganizationID: req.OrganizationId,
		Provider:       req.Provider,
		Config:         sealed,
		Enabled:        enabled,
	}
	if err := s.configDAO.UpsertOAuthConfig(cfg); err != nil {
		return nil, err
	}
	oauthmw.Invalidate(req.OrganizationId, req.Provider)

	// Re-read so created_at/updated_at reflect the persisted row.
	saved, err := s.configDAO.QueryOAuthConfigAny(req.OrganizationId, req.Provider)
	if err != nil {
		return nil, err
	}
	view, err := toProviderConfig(saved)
	if err != nil {
		return nil, err
	}
	return &oauthmodel.SetOAuthConfigResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Config:  view,
	}, nil
}

// GetOAuthConfig returns one provider config with sensitive settings masked.
func (s *OAuthService) GetOAuthConfig(req *oauthmodel.GetOAuthConfigRequest) (*oauthmodel.GetOAuthConfigResponse, error) {
	if req.OrganizationId == 0 || req.Provider == "" {
		return nil, errno.ParamErr
	}
	cfg, err := s.configDAO.QueryOAuthConfigAny(req.OrganizationId, req.Provider)
	if err != nil {
		return nil, err
	}
	view, err := toProviderConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &oauthmodel.GetOAuthConfigResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Config:  view,
	}, nil
}

// ListOAuthConfigs returns every provider config of an organization, masked.
func (s *OAuthService) ListOAuthConfigs(req *oauthmodel.ListOAuthConfigsRequest) (*oauthmodel.ListOAuthConfigsResponse, error) {
	if req.OrganizationId == 0 {
		return nil, errno.ParamErr
	}
	rows, err := s.configDAO.ListOAuthConfigs(req.OrganizationId)
	if err != nil {
		return nil, err
	}
	views := make([]*oauthmodel.OAuthProviderConfig, 0, len(rows))
	for _, row := range rows {
		view, err := toProviderConfig(row)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return &oauthmodel.ListOAuthConfigsResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Configs: views,
		Total:   int64(len(views)),
	}, nil
}

// DeleteOAuthConfig removes an organization's provider config and invalidates
// the cached provider.
func (s *OAuthService) DeleteOAuthConfig(req *oauthmodel.DeleteOAuthConfigRequest) (*oauthmodel.DeleteOAuthConfigResponse, error) {
	if req.OrganizationId == 0 || req.Provider == "" {
		return nil, errno.ParamErr
	}
	if err := s.configDAO.DeleteOAuthConfig(req.OrganizationId, req.Provider); err != nil {
		return nil, err
	}
	oauthmw.Invalidate(req.OrganizationId, req.Provider)
	return &oauthmodel.DeleteOAuthConfigResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}, nil
}

// GetAuthorizeURL builds the provider consent URL. A CSRF state is generated
// (or echoed) and stored for oauthStateTTL; the login step consumes it.
func (s *OAuthService) GetAuthorizeURL(req *oauthmodel.GetOAuthAuthorizeURLRequest) (*oauthmodel.GetOAuthAuthorizeURLResponse, error) {
	if req.OrganizationId == 0 || req.Provider == "" {
		return nil, errno.ParamErr
	}
	state := req.State
	if state == "" {
		generated, err := newOAuthState()
		if err != nil {
			return nil, err
		}
		state = generated
	}
	if err := oauthStateStore.Store(OAuthStateScene, state, "1", oauthStateTTL); err != nil {
		return nil, err
	}
	url, err := oauthmw.AuthCodeURLWithRedirect(s.ctx, req.OrganizationId, req.Provider, state, req.RedirectUri)
	if err != nil {
		return nil, err
	}
	return &oauthmodel.GetOAuthAuthorizeURLResponse{
		Code:         errno.SuccessCode,
		Message:      errno.SuccessMsg,
		AuthorizeUrl: url,
		State:        state,
	}, nil
}

// toProviderConfig decrypts a stored row into the API view, masking secret-ish
// settings (any key containing secret / password / token / private).
func toProviderConfig(row *db.OAuthConfig) (*oauthmodel.OAuthProviderConfig, error) {
	plain, err := oauthmw.Decrypt(row.Config)
	if err != nil {
		return nil, err
	}
	settings, err := decodeSettings(plain)
	if err != nil {
		return nil, err
	}
	return &oauthmodel.OAuthProviderConfig{
		OrganizationId: row.OrganizationID,
		Provider:       row.Provider,
		Settings:       maskSettings(settings),
		Enabled:        row.Enabled == 1,
		CreatedAt:      row.CreatedAt.Unix(),
		UpdatedAt:      row.UpdatedAt.Unix(),
	}, nil
}

// decodeSettings tolerates non-string JSON values (e.g. a numeric timeout) by
// rendering them as JSON text.
func decodeSettings(plain []byte) (map[string]string, error) {
	var raw map[string]any
	if err := json.Unmarshal(plain, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
			continue
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		out[k] = string(b)
	}
	return out, nil
}

// maskSettings copies settings, masking values of secret-looking keys.
func maskSettings(settings map[string]string) map[string]string {
	out := make(map[string]string, len(settings))
	for k, v := range settings {
		if isSensitiveKey(k) && v != "" {
			out[k] = maskSecret(v)
			continue
		}
		out[k] = v
	}
	return out
}

// isSensitiveKey reports whether a setting key holds a credential.
func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "secret") ||
		strings.Contains(k, "password") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "private")
}

// maskSecret keeps a 2-character hint so operators can tell which credential is
// configured without exposing it.
func maskSecret(v string) string {
	r := []rune(v)
	if len(r) <= 2 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:2]) + strings.Repeat("*", len(r)-2)
}

// newOAuthState returns a 256-bit random state value.
func newOAuthState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
