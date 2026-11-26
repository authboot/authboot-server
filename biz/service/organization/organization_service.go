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

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"gorm.io/gorm"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/model/common"
	organization "github.com/authboot/authboot-server/biz/model/organization"
	"github.com/authboot/authboot-server/biz/mw/audit"
	"github.com/authboot/authboot-server/biz/mw/minio"
	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/authboot/authboot-server/pkg/utils"
)

type OrganizationService struct {
	ctx context.Context
	c   *app.RequestContext

	organizationDAO           *db.OrganizationDAO
	organizationMembershipDAO *db.OrganizationMembershipDAO
}

// NewOrganizationService create organization service
func NewOrganizationService(ctx context.Context, c *app.RequestContext) *OrganizationService {
	return &OrganizationService{
		ctx:                       ctx,
		c:                         c,
		organizationDAO:           db.IOrganizationDAO,
		organizationMembershipDAO: db.IOrganizationMembershipDAO,
	}
}

// CreateOrganization provisions a new organization (== a organization).
func (s *OrganizationService) CreateOrganization(req *organization.CreateOrganizationRequest) (*organization.Organization, error) {
	org := &db.Organization{
		Name:   req.Name,
		Code:   req.Code,
		Logo:   utils.NormalizeMinioRef(req.Logo),
		Status: constants.StatusEnabled,
	}
	accountID := s.c.GetInt64("current_user_id")
	if accountID <= 0 {
		return nil, errno.AuthorizationFailedErr
	}
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if _, err := db.NewOrganizationDAO(tx).CreateOrganization(org); err != nil {
			return err
		}
		_, err := db.NewOrganizationMembershipDAO(tx).CreateMembership(&db.OrganizationMembership{
			OrganizationID: org.ID, AccountID: accountID, Role: "owner", Status: db.MembershipActive,
		})
		return err
	}); err != nil {
		return nil, err
	}
	audit.Annotate(s.c, func(e *audit.Entry) {
		e.Action = "organization.create"
		e.ResourceType = "organization"
		e.ResourceID = strconv.FormatInt(org.ID, 10)
		e.After = auditJSON(org)
		e.Success = true
	})
	return toOrganizationInfo(org), nil
}

// ListOrganizations returns all organizations (organization view).
func (s *OrganizationService) ListOrganizations() ([]*organization.Organization, error) {
	var orgs []*db.Organization
	if err := db.DB.Model(&db.Organization{}).
		Joins("JOIN tb_organization_membership m ON m.organization_id = tb_organization.id").
		Where("m.account_id = ? AND m.status = ?", s.c.GetInt64("current_user_id"), db.MembershipActive).
		Select("tb_organization.*").Order("tb_organization.id").Find(&orgs).Error; err != nil {
		return nil, err
	}
	infos := make([]*organization.Organization, 0, len(orgs))
	for _, org := range orgs {
		infos = append(infos, toOrganizationInfo(org))
	}
	return infos, nil
}

// DisableOrganization disables an organization by id.
func (s *OrganizationService) DisableOrganization(organizationId int64) error {
	if _, err := s.organizationDAO.QueryOrganizationByID(organizationId); err != nil {
		return err
	}
	if err := s.organizationDAO.SetOrganizationStatus(organizationId, constants.StatusDisabled); err != nil {
		return err
	}
	audit.Annotate(s.c, func(e *audit.Entry) {
		e.Action = "organization.disable"
		e.ResourceType = "organization"
		e.ResourceID = strconv.FormatInt(organizationId, 10)
		e.Success = true
	})
	return nil
}

// GetOrganization creates an invitation binding an email to an org admin role.
// It returns the invitation token that the invitee redeems on accept.
func (s *OrganizationService) GetOrganization(organizationId int64) (*organization.Organization, error) {
	organization, err := s.organizationDAO.QueryOrganizationByID(organizationId)
	if err != nil {
		return nil, err
	}
	return toOrganizationInfo(organization), nil
}

// UpdateOrganization updates an existing organization's mutable fields by id.
// Only non-zero fields on the request are applied, leaving others untouched.
func (s *OrganizationService) UpdateOrganization(req *organization.UpdateOrganizationRequest) (*organization.Organization, error) {
	org, err := s.organizationDAO.QueryOrganizationByID(req.OrganizationId)
	if err != nil {
		return nil, err
	}
	before := auditJSON(org)
	var staleLogo string
	if req.Name != "" {
		org.Name = req.Name
	}
	if req.Code != "" {
		org.Code = req.Code
	}
	if req.Logo != "" {
		newLogo := utils.NormalizeMinioRef(req.Logo)
		// 仅在 logo 实际变化时更新，并只保留最近一次修改的旧 logo
		if newLogo != org.Logo {
			if org.Logo != "" {
				staleLogo = org.PreviousLogo
				org.PreviousLogo = org.Logo
			}
			org.Logo = newLogo
		}
	}
	if req.Status != common.Status_STATUS_UNKNOWN {
		org.Status = int8(req.Status)
	}
	if err := s.organizationDAO.UpdateOrganization(org); err != nil {
		return nil, err
	}
	// DB 更新成功后，清理不再被引用的更早一代旧文件
	deleteStaleMinioLogo(s.ctx, staleLogo)
	audit.Annotate(s.c, func(e *audit.Entry) {
		e.Action = "organization.update"
		e.ResourceType = "organization"
		e.ResourceID = strconv.FormatInt(org.ID, 10)
		e.Before = before
		e.After = auditJSON(org)
		e.Success = true
	})
	return toOrganizationInfo(org), nil
}

func (s *OrganizationService) UploadOrganizationLogo(req *organization.UploadOrganizationLogoRequest) (*organization.UploadOrganizationLogoResponse, error) {
	org, err := s.organizationDAO.QueryOrganizationByID(req.OrganizationId)
	if err != nil {
		return nil, err
	}

	v, _ := s.c.Get("current_user_id")
	userID, _ := v.(int64)

	// 图片文件通过 multipart/form-data 上传，表单字段名为 logo
	file, err := s.c.FormFile("logo")
	if err != nil {
		return nil, err
	}
	file.Filename = utils.NewFileName(userID, time.Now().Unix()) + path.Ext(file.Filename)

	uploadInfo, err := minio.PutToBucket(s.ctx, constants.MinioImgBucketName, file)
	if err != nil {
		return nil, err
	}
	hlog.CtxInfof(s.ctx, "logo upload size:"+strconv.FormatInt(uploadInfo.Size, 10))

	// 只保留最近一次修改的旧 logo：替换前把当前 logo 记为 previous_logo，
	// 更早一代的 previous_logo 待 DB 更新成功后再从 minio 删除
	var staleLogo string
	if org.Logo != "" {
		staleLogo = org.PreviousLogo
		org.PreviousLogo = org.Logo
	}

	// DB 中存 "bucket/filename" 相对路径，返回给前端的是可直接访问的完整 URL
	org.Logo = constants.MinioImgBucketName + "/" + file.Filename
	if err := s.organizationDAO.UpdateOrganization(org); err != nil {
		return nil, err
	}
	deleteStaleMinioLogo(s.ctx, staleLogo)

	return &organization.UploadOrganizationLogoResponse{
		Code:         errno.SuccessCode,
		Message:      errno.SuccessMsg,
		Logo:         utils.MinioPublicURL(org.Logo),
		Organization: toOrganizationInfo(org),
	}, nil
}

func (s *OrganizationService) LeaveOrganization(req *organization.LeaveOrganizationRequest) error {
	v, ok := s.c.Get("current_user_id")
	if !ok {
		return errno.AuthorizationFailedErr
	}
	accountID, ok := v.(int64)
	if !ok {
		return errno.AuthorizationFailedErr
	}

	// 确认组织存在
	if _, err := s.organizationDAO.QueryOrganizationByID(req.OrganizationId); err != nil {
		return err
	}

	// 删除当前账号在该组织的成员关系；不是成员则返回 MembershipNotExistErr
	m, err := s.organizationMembershipDAO.QueryMembership(req.OrganizationId, accountID)
	if err != nil || m.Role == "owner" {
		return errno.AuthorizationFailedErr
	}
	return s.organizationMembershipDAO.LeaveOrganization(req.OrganizationId, accountID)
}

// GetOrganizationSettings 返回组织的设置，未配置的字段按默认值补齐后返回。
func (s *OrganizationService) GetOrganizationSettings(organizationId int64) (*organization.OrganizationSettings, error) {
	settings, err := s.organizationDAO.GetOrganizationSettings(organizationId)
	if err != nil {
		return nil, err
	}
	return toOrganizationSettings(settings), nil
}

// UpdateOrganizationSettings 整体替换组织的设置（缺失字段回落默认值），并记录审计。
func (s *OrganizationService) UpdateOrganizationSettings(req *organization.UpdateOrganizationSettingsRequest) (*organization.OrganizationSettings, error) {
	if req.Settings == nil {
		return nil, errno.ParamErr
	}
	if _, err := s.organizationDAO.QueryOrganizationByID(req.OrganizationId); err != nil {
		return nil, err
	}
	before, err := s.organizationDAO.GetOrganizationSettings(req.OrganizationId)
	if err != nil {
		return nil, err
	}
	stored := fromOrganizationSettings(req.Settings)
	if err := applyMaintenanceTransition(stored, before); err != nil {
		return nil, err
	}
	if err := validatePasswordPolicy(stored.PasswordPolicy); err != nil {
		return nil, err
	}
	if err := s.organizationDAO.SaveOrganizationSettings(req.OrganizationId, stored); err != nil {
		return nil, err
	}
	// 读回生效后的设置（缺失字段按默认值补齐）用于审计与响应
	effective, err := s.organizationDAO.GetOrganizationSettings(req.OrganizationId)
	if err != nil {
		return nil, err
	}
	audit.Annotate(s.c, func(e *audit.Entry) {
		e.Action = "organization.settings.update"
		e.ResourceType = "organization"
		e.ResourceID = strconv.FormatInt(req.OrganizationId, 10)
		e.Before = auditJSON(before)
		e.After = auditJSON(effective)
		e.Success = true
	})
	return toOrganizationSettings(effective), nil
}

// GetMaintenanceNotice 返回组织的维护公告（公开接口，无需登录）。只暴露展示
// 所需字段；组织不存在或未开启维护时返回 enabled=false 且文案为空，不泄露配置。
func (s *OrganizationService) GetMaintenanceNotice(organizationId int64) (*organization.MaintenanceNotice, error) {
	if organizationId <= 0 {
		return nil, errno.ParamErr
	}
	settings, err := s.organizationDAO.GetOrganizationSettings(organizationId)
	if err != nil {
		// 不区分"组织不存在"和"读取失败"，统一当作未维护，避免被用来探测组织 id。
		return &organization.MaintenanceNotice{}, nil
	}
	if !settings.MaintenanceActive() {
		return &organization.MaintenanceNotice{}, nil
	}
	m := settings.Maintenance
	return &organization.MaintenanceNotice{
		Enabled:     true,
		Title:       m.Title,
		Message:     m.Message,
		ExpectedEnd: m.ExpectedEnd,
	}, nil
}

// PublicPasswordPolicy 返回组织生效的密码策略（公开接口用）；组织不存在时
// 返回默认策略，不暴露组织是否存在。
func (s *OrganizationService) PublicPasswordPolicy(organizationId int64) *organization.PasswordPolicy {
	p := db.EffectivePasswordPolicy(organizationId)
	return &organization.PasswordPolicy{
		MinLength:        int32(p.MinLength),
		RequireLowercase: p.RequireLowercase,
		RequireUppercase: p.RequireUppercase,
		RequireDigit:     p.RequireDigit,
		RequireSymbol:    p.RequireSymbol,
		Hint:             p.EffectiveHint(),
	}
}

// toOrganizationSettings 把 DB 层设置模型转成 API DTO；登录方式副本拷贝，
// 避免调用方修改影响持久化层缓存。
func toOrganizationSettings(s *db.OrganizationSettings) *organization.OrganizationSettings {
	if s == nil {
		return nil
	}
	out := &organization.OrganizationSettings{
		AdminTokenTtlSeconds: s.AdminTokenTTLSeconds,
	}
	if s.LoginMethods != nil {
		out.LoginMethods = &organization.LoginMethods{
			EmailPassword:  s.LoginMethods.EmailPassword,
			EmailCode:      s.LoginMethods.EmailCode,
			PhoneCode:      s.LoginMethods.PhoneCode,
			OauthProviders: append([]string(nil), s.LoginMethods.OAuthProviders...),
		}
	}
	// Always return the effective password policy (default when unset) so the
	// admin UI shows what users are actually held to.
	policy := s.PasswordPolicy
	if policy == nil {
		policy = db.DefaultPasswordPolicy()
	}
	out.PasswordPolicy = &organization.PasswordPolicy{
		MinLength:        int32(policy.MinLength),
		RequireLowercase: policy.RequireLowercase,
		RequireUppercase: policy.RequireUppercase,
		RequireDigit:     policy.RequireDigit,
		RequireSymbol:    policy.RequireSymbol,
		Hint:             policy.Hint,
	}
	// Always return a maintenance object so the admin UI never has to special
	// case "never configured".
	out.Maintenance = &organization.Maintenance{}
	if s.Maintenance != nil {
		out.Maintenance = &organization.Maintenance{
			Enabled:     s.Maintenance.Enabled,
			Title:       s.Maintenance.Title,
			Message:     s.Maintenance.Message,
			ExpectedEnd: s.Maintenance.ExpectedEnd,
			StartedAt:   s.Maintenance.StartedAt,
		}
	}
	return out
}

const (
	maintenanceTitleMax   = 80
	maintenanceMessageMax = 500
	passwordHintMax       = 200
)

// validatePasswordPolicy rejects out-of-range lengths and over-long hints
// instead of silently clamping, so the admin sees the mistake.
func validatePasswordPolicy(p *db.PasswordPolicy) error {
	if p == nil {
		return nil
	}
	if p.MinLength < db.PasswordMinLengthFloor || p.MinLength > db.PasswordMaxLength {
		return fmt.Errorf("password min_length must be between %d and %d", db.PasswordMinLengthFloor, db.PasswordMaxLength)
	}
	if len([]rune(p.Hint)) > passwordHintMax {
		return fmt.Errorf("password hint exceeds %d characters", passwordHintMax)
	}
	return nil
}

// applyMaintenanceTransition validates the submitted maintenance block and
// stamps started_at: set when maintenance turns on, kept while it stays on,
// cleared when it turns off. started_at from the client is ignored.
func applyMaintenanceTransition(next, prev *db.OrganizationSettings) error {
	if next.Maintenance == nil {
		return nil
	}
	m := next.Maintenance
	m.Title = strings.TrimSpace(m.Title)
	m.Message = strings.TrimSpace(m.Message)
	if len([]rune(m.Title)) > maintenanceTitleMax || len([]rune(m.Message)) > maintenanceMessageMax {
		return errno.ParamErr
	}
	if m.Enabled && (m.Title == "" || m.Message == "") {
		return fmt.Errorf("maintenance notice title and message are required to turn maintenance on")
	}
	switch {
	case !m.Enabled:
		m.StartedAt = 0
	case prev != nil && prev.MaintenanceActive():
		m.StartedAt = prev.Maintenance.StartedAt
	default:
		m.StartedAt = time.Now().Unix()
	}
	return nil
}

// fromOrganizationSettings 把 API DTO 转成 DB 层设置模型用于持久化。
func fromOrganizationSettings(s *organization.OrganizationSettings) *db.OrganizationSettings {
	if s == nil {
		return nil
	}
	stored := &db.OrganizationSettings{
		AdminTokenTTLSeconds: s.AdminTokenTtlSeconds,
	}
	if s.LoginMethods != nil {
		stored.LoginMethods = &db.LoginMethods{
			EmailPassword:  s.LoginMethods.EmailPassword,
			EmailCode:      s.LoginMethods.EmailCode,
			PhoneCode:      s.LoginMethods.PhoneCode,
			OAuthProviders: append([]string(nil), s.LoginMethods.OauthProviders...),
		}
	}
	if s.PasswordPolicy != nil {
		stored.PasswordPolicy = &db.PasswordPolicy{
			MinLength:        int(s.PasswordPolicy.MinLength),
			RequireLowercase: s.PasswordPolicy.RequireLowercase,
			RequireUppercase: s.PasswordPolicy.RequireUppercase,
			RequireDigit:     s.PasswordPolicy.RequireDigit,
			RequireSymbol:    s.PasswordPolicy.RequireSymbol,
			Hint:             strings.TrimSpace(s.PasswordPolicy.Hint),
		}
	}
	if s.Maintenance != nil {
		stored.Maintenance = &db.Maintenance{
			Enabled:     s.Maintenance.Enabled,
			Title:       s.Maintenance.Title,
			Message:     s.Maintenance.Message,
			ExpectedEnd: s.Maintenance.ExpectedEnd,
		}
	}
	return stored
}

// toOrganizationInfo 把 DB 模型转成对外的组织信息；logo 统一拼接成完整访问地址。
func toOrganizationInfo(org *db.Organization) *organization.Organization {
	return &organization.Organization{
		Id:     org.ID,
		Name:   org.Name,
		Code:   org.Code,
		Logo:   utils.MinioPublicURL(org.Logo),
		Status: common.Status(org.Status),
	}
}

// auditJSON marshals a value for an audit Before/After field, best-effort. Only
// pass already-sanitized data (no passwords, tokens, or secrets).
func auditJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// appendLogoHistory 已废弃：改为只保留最近一次修改的旧 logo（PreviousLogo 字段），
// 更早一代的旧文件由 deleteStaleMinioLogo 从 minio 中清理。

// deleteStaleMinioLogo 删除不再被引用的旧 logo 对象。只清理属于本服务图片桶的
// "bucket/key" 相对路径，外部 URL / 空值 / 非本桶引用一律跳过，避免误删。
func deleteStaleMinioLogo(ctx context.Context, ref string) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return
	}
	bucket, key, ok := strings.Cut(ref, "/")
	if !ok || bucket != constants.MinioImgBucketName || key == "" {
		return
	}
	if err := minio.RemoveObject(ctx, bucket, key); err != nil {
		hlog.CtxInfof(ctx, "remove stale logo %s failed: %v", ref, err)
		return
	}
	hlog.CtxInfof(ctx, "remove stale logo %s", ref)
}
