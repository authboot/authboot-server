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
