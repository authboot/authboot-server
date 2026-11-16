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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// WechatConfig holds the credentials for the 微信 (开放平台 / 网站应用) OAuth2
// login adapter.
type WechatConfig struct {
	AppID       string `json:"app_id"`       // 微信开放平台应用 AppID
	AppSecret   string `json:"app_secret"`   // 微信开放平台应用 AppSecret
	RedirectURI string `json:"redirect_uri"` // callback URL registered on 微信开放平台
	// Scope is the authorization scope. Defaults to "snsapi_login" (网站扫码登录).
	Scope string `json:"scope,omitempty"`
	// Timeout bounds each HTTP request to the 微信 API.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// wechatProvider implements Provider against the 微信 OAuth2 endpoints using
// only the standard library, so no vendor SDK dependency is introduced.
type wechatProvider struct {
	cfg    WechatConfig
	client *http.Client
}

// NewWechatProvider builds a 微信-backed identity Provider.
func NewWechatProvider(cfg WechatConfig) Provider {
	if cfg.Scope == "" {
		cfg.Scope = "snsapi_login"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &wechatProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

func (p *wechatProvider) Name() string { return "wechat" }

// AuthCodeURL builds the 微信 qrconnect consent URL. The #wechat_redirect
// fragment is required by 微信 for the redirect to take effect.
func (p *wechatProvider) AuthCodeURL(state string) string {
	q := url.Values{}
	q.Set("appid", p.cfg.AppID)
	q.Set("redirect_uri", p.cfg.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", p.cfg.Scope)
	q.Set("state", state)
	return "https://open.weixin.qq.com/connect/qrconnect?" + q.Encode() + "#wechat_redirect"
}

// Exchange calls sns/oauth2/access_token to swap the code for a token. 微信
// returns openid (and unionid) together with the token in this one call.
func (p *wechatProvider) Exchange(ctx context.Context, code string) (*Token, error) {
	if err := validateCode(code); err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("appid", p.cfg.AppID)
	q.Set("secret", p.cfg.AppSecret)
	q.Set("code", code)
	q.Set("grant_type", "authorization_code")
	reqURL := "https://api.weixin.qq.com/sns/oauth2/access_token?" + q.Encode()

	var out struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		OpenID       string `json:"openid"`
		Scope        string `json:"scope"`
		ErrCode      int    `json:"errcode"`
		ErrMsg       string `json:"errmsg"`
	}
	if err := p.getJSON(ctx, reqURL, &out); err != nil {
		return nil, fmt.Errorf("oauth/wechat: exchange: %w", err)
	}
	if out.ErrCode != 0 {
		return nil, fmt.Errorf("oauth/wechat: exchange failed: errcode=%d errmsg=%s", out.ErrCode, out.ErrMsg)
	}

	return &Token{
		AccessToken:  out.AccessToken,
		RefreshToken: out.RefreshToken,
		ExpiresIn:    out.ExpiresIn,
		OpenID:       out.OpenID,
		Scope:        out.Scope,
	}, nil
}

// UserInfo calls sns/userinfo to fetch the profile for the token's openid.
func (p *wechatProvider) UserInfo(ctx context.Context, tok *Token) (*UserInfo, error) {
	if tok == nil || tok.AccessToken == "" {
		return nil, fmt.Errorf("oauth/wechat: token is nil or missing access_token")
	}
	if tok.OpenID == "" {
		return nil, fmt.Errorf("oauth/wechat: token is missing openid")
	}

	q := url.Values{}
	q.Set("access_token", tok.AccessToken)
	q.Set("openid", tok.OpenID)
	q.Set("lang", "zh_CN")
	reqURL := "https://api.weixin.qq.com/sns/userinfo?" + q.Encode()

	var out struct {
		OpenID     string `json:"openid"`
		UnionID    string `json:"unionid"`
		Nickname   string `json:"nickname"`
		HeadImgURL string `json:"headimgurl"`
		ErrCode    int    `json:"errcode"`
		ErrMsg     string `json:"errmsg"`
	}
	if err := p.getJSON(ctx, reqURL, &out); err != nil {
		return nil, fmt.Errorf("oauth/wechat: userinfo: %w", err)
	}
	if out.ErrCode != 0 {
		return nil, fmt.Errorf("oauth/wechat: userinfo failed: errcode=%d errmsg=%s", out.ErrCode, out.ErrMsg)
	}

	raw := map[string]any{
		"openid":     out.OpenID,
		"unionid":    out.UnionID,
		"nickname":   out.Nickname,
		"headimgurl": out.HeadImgURL,
	}
	return &UserInfo{
		Provider:  p.Name(),
		OpenID:    out.OpenID,
		UnionID:   out.UnionID,
		Nickname:  out.Nickname,
		AvatarURL: out.HeadImgURL,
		Raw:       raw,
	}, nil
}

// getJSON performs a GET and decodes the JSON body into v. 微信 returns errors
// as a 200 response with an errcode field, so the caller inspects errcode.
func (p *wechatProvider) getJSON(ctx context.Context, reqURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("decode response (status %d): %s", resp.StatusCode, string(body))
	}
	return nil
}
