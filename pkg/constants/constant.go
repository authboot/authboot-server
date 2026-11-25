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

package constants

import (
	"fmt"
	"os"
	"strings"
)

// GetMySQLDSN retrieves the MySQL DSN from env, with fatal exit if unset.
func GetMySQLDSN() string {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		fmt.Fprintf(os.Stderr, "fatal: DB_DSN is not set\n")
		os.Exit(1)
	}
	return dsn
}

// GetMinioEndpoint retrieves the MinIO endpoint from env, with fatal exit if unset.
func GetMinioEndpoint() string {
	ep := os.Getenv("MINIO_ENDPOINT")
	if ep == "" {
		fmt.Fprintf(os.Stderr, "fatal: MINIO_ENDPOINT is not set\n")
		os.Exit(1)
	}
	return ep
}

// GetMinioPublicBaseURL 返回对象存储的公网访问前缀（如 http://10.99.64.82:8999/）。
// 未配置时返回空串，调用方可据此回退为相对路径，属于可选配置。
func GetMinioPublicBaseURL() string {
	return strings.TrimSpace(os.Getenv("MINIO_PUBLIC_BASE_URL"))
}

// GetMinioAccessKeyID retrieves the MinIO access key from env, with fatal exit if unset.
func GetMinioAccessKeyID() string {
	key := os.Getenv("MINIO_ACCESS_KEY_ID")
	if key == "" {
		fmt.Fprintf(os.Stderr, "fatal: MINIO_ACCESS_KEY_ID is not set\n")
		os.Exit(1)
	}
	return key
}

// GetMinioSecretAccessKey retrieves the MinIO secret key from env, with fatal exit if unset.
func GetMinioSecretAccessKey() string {
	key := os.Getenv("MINIO_SECRET_ACCESS_KEY")
	if key == "" {
		fmt.Fprintf(os.Stderr, "fatal: MINIO_SECRET_ACCESS_KEY is not set\n")
		os.Exit(1)
	}
	return key
}

// GetRedisAddr retrieves the Redis address from env, with fatal exit if unset.
func GetRedisAddr() string {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		fmt.Fprintf(os.Stderr, "fatal: REDIS_ADDR is not set\n")
		os.Exit(1)
	}
	return addr
}

// GetRedisPassword retrieves the Redis password from env, with fatal exit if unset.
func GetRedisPassword() string {
	return os.Getenv("REDIS_PASSWORD")
}

// connection information
const (
	MiniouseSSL = false
)

// constants in the project
const (
	CommentTableName = "comments"

	MinioVideoBucketName = "videobucket"
	MinioImgBucketName   = "imagebucket"

	TestSign       = "测试账号！ offer"
	TestAva        = "avatar/test1.jpg"
	TestBackground = "background/test1.png"
)

// ---------------------------------------------------------------------------
// authboot multi-tenant platform constants
// ---------------------------------------------------------------------------

// table names for the auth platform models
const (
	OrganizationTableName           = "tb_organizations"
	PlatformAccountTableName        = "tb_platform_accounts"
	OrganizationMembershipTableName = "tb_organization_memberships"
	AppClientTableName              = "tb_app_clients"
	UserTableName                   = "tb_users"
	UserIdentityTableName           = "tb_user_identities"
	OrganizationInvitationTableName = "tb_organization_invitations"
	OAuthConfigTableName            = "tb_oauth_configs"
	MessageProviderConfigTableName  = "tb_message_provider_configs"
	AdminAuditLogTableName          = "tb_admin_audit_logs"
	UserAddressTableName            = "tb_user_addresses"
	UserLoginLogTableName           = "tb_user_login_logs"
	AdminUserTableName              = "tb_admin_users"

	// admin / user symmetric security tables (login log, audit log, session,
	// device). Sessions are persisted for audit/inspection; the hot path
	// (token refresh, revocation) still lives in Redis.
	AdminLoginLogTableName = "tb_admin_login_logs"
	UserAuditLogTableName  = "tb_user_audit_logs"
	AdminSessionTableName  = "tb_admin_sessions"
	UserSessionTableName   = "tb_user_sessions"
	AdminDeviceTableName   = "tb_admin_devices"
	UserDeviceTableName    = "tb_user_devices"

	// per-organization legal documents (privacy policy / user agreement)
	OrganizationLegalDocVersionTableName = "tb_organization_legal_doc_versions"
)

// generic status values shared by the platform models
const (
	StatusEnabled  = 1
	StatusDisabled = 2
)

// JWT subjects ("admin" / "user"): namespaced in redis session keys and used
// to pick the session persistence table (tb_admin_sessions / tb_user_sessions).
const (
	AdminSubject = "admin"
	UserSubject  = "user"
)

// identity types stored in user_identities.identity_type
const (
	IdentityTypeEmail    = "email"
	IdentityTypePhone    = "phone"
	IdentityTypeUsername = "username"
	IdentityTypeWechat   = "wechat_openid"
	IdentityTypeUnionID  = "wechat_unionid"
	IdentityTypeApple    = "apple"
	IdentityTypeGoogle   = "google"
)

// app client types (login entries) that share an organization user pool
const (
	ClientTypeIOS         = "ios"
	ClientTypeAndroid     = "android"
	ClientTypeH5          = "h5"
	ClientTypeMiniProgram = "mini_program"
)

// platform account / membership roles
const (
	RoleSuperAdmin = "super_admin"
	RoleOrgAdmin   = "org_admin"
	RoleOrgMember  = "org_member"
)

// invitation status values
const (
	InvitationStatusPending  = "pending"
	InvitationStatusAccepted = "accepted"
	InvitationStatusExpired  = "expired"
	InvitationStatusRevoked  = "revoked"
)

// token / session related constants
const (
	AppTokenTTL     = 24 * 60 * 60     // seconds
	AdminTokenTTL   = 8 * 60 * 60      // seconds
	InvitationTTL   = 7 * 24 * 60 * 60 // seconds
	AppAuthCtxKey   = "app_auth_ctx"   // key stored in RequestContext
	AdminAuthCtxKey = "admin_auth_ctx" // key stored in RequestContext

	// AppAccessTokenTTLSeconds 是 admin/user access token 的全局默认有效时长
	// （秒），即 biz/mw/jwt 中 appAccessTTL 的取值来源。组织可经
	// tb_organization.settings.admin_token_ttl_seconds 单独覆盖 admin 侧时长。
	AppAccessTokenTTLSeconds = 15 * 60
)

// OAuthProviders 是组织设置中可选的三方登录提供商列表，名称与
// biz/mw/oauth 的 provider 名一致（buildProviderFromConfig 目前仅实现 wechat，
// 其余提供商需在 oauth 层补齐实现后才会真正可用）。
var OAuthProviders = []string{"wechat", "google", "apple", "github", "alipay"}
