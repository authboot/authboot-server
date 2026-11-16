// Package legaldocs 内置的法律文档默认模板（隐私政策 / 用户协议）。
// 组织未自定义时，公开读取接口返回这些模板内容；管理端可以基于模板
// 修改后保存为组织自己的版本。
package legaldocs

import _ "embed"

//go:embed templates/privacy_policy.md
var PrivacyPolicyTemplate string

//go:embed templates/user_agreement.md
var UserAgreementTemplate string

// DefaultTitle 返回文档类型的默认标题。
func DefaultTitle(docType string) string {
	switch docType {
	case "privacy_policy":
		return "隐私政策"
	case "user_agreement":
		return "用户协议"
	default:
		return docType
	}
}

// DefaultContent 返回文档类型的默认模板内容；未知类型返回空串。
func DefaultContent(docType string) string {
	switch docType {
	case "privacy_policy":
		return PrivacyPolicyTemplate
	case "user_agreement":
		return UserAgreementTemplate
	default:
		return ""
	}
}
