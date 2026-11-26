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

package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/authboot/authboot-server/pkg/constants"
)

// OrganizationSettings 是组织级配置（存储于 tb_organization.settings JSON 列）。
// 遵循"整体替换"语义：写入方（管理端 PUT）每次提交完整的设置对象；
// 读取时字段缺失按默认值补齐，因此可以安全地增量加字段。
//
// 默认值保持与引入本配置前一致：
//   - AdminTokenTTLSeconds == 0  -> 使用 appAccessTTL（15 分钟）
//   - LoginMethods 为 nil        -> 全部登录方式开启，OAuth 允许所有已支持提供商
type OrganizationSettings struct {
	// AdminTokenTTLSeconds 组织 admin access token 有效时长（秒），0 表示用默认值
	AdminTokenTTLSeconds int64 `json:"admin_token_ttl_seconds"`
	// LoginMethods 组织下普通用户的授权登录方式开关
	LoginMethods *LoginMethods `json:"login_methods"`
	// Maintenance 维护模式；nil 表示未开启且没有保存过公告
	Maintenance *Maintenance `json:"maintenance,omitempty"`
	// PasswordPolicy 普通用户密码策略；nil 表示默认（仅长度 8–72）
	PasswordPolicy *PasswordPolicy `json:"password_policy,omitempty"`
}

// Maintenance 维护模式：Enabled 为 true 时组织下普通用户的登录 / 注册 / 找回密码
// 被拒绝并返回公告标题。公告可以在未开启时预先保存。
type Maintenance struct {
	Enabled     bool   `json:"enabled"`
	Title       string `json:"title"`
	Message     string `json:"message"`
	ExpectedEnd int64  `json:"expected_end"` // unix 秒，0 表示未设置
	StartedAt   int64  `json:"started_at"`   // unix 秒，开启时写入，关闭时清零
}

// MaintenanceActive 报告组织是否处于维护模式。
func (s *OrganizationSettings) MaintenanceActive() bool {
	return s != nil && s.Maintenance != nil && s.Maintenance.Enabled
}

// LoginMethods 定义组织下普通用户（非 admin）可用的登录方式。字段名即开关：
// true 表示该方式允许使用。oauth_providers 为空数组表示全部关闭，为 nil 表示用默认列表。
type LoginMethods struct {
	EmailPassword  bool     `json:"email_password"`  // 邮箱 + 密码
	EmailCode      bool     `json:"email_code"`      // 邮箱验证码
	PhoneCode      bool     `json:"phone_code"`      // 手机验证码
	OAuthProviders []string `json:"oauth_providers"` // 允许的三方登录提供商
}

// DefaultOrganizationSettings 返回与引入组织设置前行为一致的默认配置。
func DefaultOrganizationSettings() *OrganizationSettings {
	return &OrganizationSettings{
		AdminTokenTTLSeconds: constants.AppAccessTokenTTLSeconds,
		LoginMethods:         DefaultLoginMethods(),
	}
}

// DefaultLoginMethods 返回全部登录方式开启的默认配置。
func DefaultLoginMethods() *LoginMethods {
	return &LoginMethods{
		EmailPassword:  true,
		EmailCode:      true,
		PhoneCode:      true,
		OAuthProviders: append([]string(nil), constants.OAuthProviders...),
	}
}

// parseOrganizationSettings 解析 settings JSON 并补齐默认值。
// 空串 / 非法 JSON 都回退到默认配置（非法 JSON 不应阻塞登录鉴权）。
func parseOrganizationSettings(raw string) *OrganizationSettings {
	def := DefaultOrganizationSettings()
	if raw == "" {
		return def
	}
	var s OrganizationSettings
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return def
	}
	if s.AdminTokenTTLSeconds <= 0 {
		s.AdminTokenTTLSeconds = def.AdminTokenTTLSeconds
	}
	if s.LoginMethods == nil {
		s.LoginMethods = DefaultLoginMethods()
	} else if s.LoginMethods.OAuthProviders == nil {
		s.LoginMethods.OAuthProviders = append([]string(nil), constants.OAuthProviders...)
	}
	if s.PasswordPolicy != nil {
		s.PasswordPolicy.Normalize()
	}
	return &s
}

// GetOrganizationSettings 读取组织的设置，字段缺失时按默认值补齐。
func (d *OrganizationDAO) GetOrganizationSettings(id int64) (*OrganizationSettings, error) {
	org, err := d.QueryOrganizationByID(id)
	if err != nil {
		return nil, err
	}
	return parseOrganizationSettings(org.Settings), nil
}

// SaveOrganizationSettings 序列化并持久化组织设置。
func (d *OrganizationDAO) SaveOrganizationSettings(id int64, s *OrganizationSettings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return d.UpdateOrganizationSettings(id, string(b))
}

// AdminAccessTokenTTL 返回组织配置的 admin access token 有效时长（秒），
// 组织不存在或未配置时回退到全局默认值。
func AdminAccessTokenTTL(orgID int64) int64 {
	if orgID <= 0 {
		return constants.AppAccessTokenTTLSeconds
	}
	s, err := IOrganizationDAO.GetOrganizationSettings(orgID)
	if err != nil {
		return constants.AppAccessTokenTTLSeconds
	}
	if s.AdminTokenTTLSeconds <= 0 {
		return constants.AppAccessTokenTTLSeconds
	}
	return s.AdminTokenTTLSeconds
}

// ---------------------------------------------------------------------------
// Password policy
// ---------------------------------------------------------------------------

// Password length bounds. The upper bound is bcrypt's 72-byte input limit and
// is not configurable; the lower bound is the floor an admin may set.
const (
	PasswordMinLengthFloor = 8
	PasswordMaxLength      = 72
)

// PasswordPolicy is the structured password rule applied to organization
// users when they register, change or reset a password. Structured flags
// instead of a regex keep validation trivial on the server (no RE2 lookahead
// limits) and let clients render a checklist.
type PasswordPolicy struct {
	MinLength        int    `json:"min_length"`
	RequireLowercase bool   `json:"require_lowercase"`
	RequireUppercase bool   `json:"require_uppercase"`
	RequireDigit     bool   `json:"require_digit"`
	RequireSymbol    bool   `json:"require_symbol"`
	Hint             string `json:"hint"`
}

// DefaultPasswordPolicy matches the rule applied before policies existed:
// length only, 8–72 characters.
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{MinLength: PasswordMinLengthFloor}
}

// Normalize clamps the length and trims the hint. It never fails: an invalid
// stored value degrades to the nearest valid one.
func (p *PasswordPolicy) Normalize() {
	if p.MinLength < PasswordMinLengthFloor {
		p.MinLength = PasswordMinLengthFloor
	}
	if p.MinLength > PasswordMaxLength {
		p.MinLength = PasswordMaxLength
	}
	p.Hint = strings.TrimSpace(p.Hint)
}

// Check reports whether password satisfies the policy. Character classes are
// evaluated per rune so non-ASCII letters count as letters.
func (p *PasswordPolicy) Check(password string) bool {
	if len(password) < p.MinLength || len(password) > PasswordMaxLength {
		return false
	}
	var lower, upper, digit, symbol bool
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	if p.RequireLowercase && !lower {
		return false
	}
	if p.RequireUppercase && !upper {
		return false
	}
	if p.RequireDigit && !digit {
		return false
	}
	if p.RequireSymbol && !symbol {
		return false
	}
	return true
}

// EffectiveHint returns the admin's hint, or a sentence generated from the
// rules when none was set.
func (p *PasswordPolicy) EffectiveHint() string {
	if p.Hint != "" {
		return p.Hint
	}
	parts := []string{}
	if p.RequireLowercase {
		parts = append(parts, "a lowercase letter")
	}
	if p.RequireUppercase {
		parts = append(parts, "an uppercase letter")
	}
	if p.RequireDigit {
		parts = append(parts, "a number")
	}
	if p.RequireSymbol {
		parts = append(parts, "a symbol")
	}
	msg := fmt.Sprintf("Use at least %d characters", p.MinLength)
	if len(parts) > 0 {
		msg += ", including " + strings.Join(parts, ", ")
	}
	return msg + "."
}

// EffectivePasswordPolicy returns the policy for orgID, falling back to the
// default when the org is unknown or has none configured.
func EffectivePasswordPolicy(orgID int64) *PasswordPolicy {
	if orgID <= 0 {
		return DefaultPasswordPolicy()
	}
	s, err := IOrganizationDAO.GetOrganizationSettings(orgID)
	if err != nil || s.PasswordPolicy == nil {
		return DefaultPasswordPolicy()
	}
	return s.PasswordPolicy
}
