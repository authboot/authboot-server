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

// Package admin implements platform-admin self-service: viewing/updating the
// signed-in admin's own profile and preference settings. The acting account is
// taken from the admin token (AdminSessionAuth), never from the request, and
// this is a different identity system from the Organization User domain.
package admin

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/datatypes"

	"github.com/authboot/authboot-server/biz/dal/db"
	adminmodel "github.com/authboot/authboot-server/biz/model/admin"
	"github.com/authboot/authboot-server/biz/model/common"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/authboot/authboot-server/pkg/utils"
)

// AdminUserService serves the current admin's profile and settings.
type AdminUserService struct {
	ctx context.Context
	c   *app.RequestContext
}

// NewAdminUserService creates an admin self-service service.
func NewAdminUserService(ctx context.Context, c *app.RequestContext) *AdminUserService {
	return &AdminUserService{ctx: ctx, c: c}
}

// GetMyProfile returns the signed-in admin's account profile.
func (s *AdminUserService) GetMyProfile(req *adminmodel.GetMyProfileRequest) (*adminmodel.GetMyProfileResponse, error) {
	u, err := s.currentAdmin()
	if err != nil {
		return nil, err
	}
	return &adminmodel.GetMyProfileResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Profile: toAdminAccount(u),
	}, nil
}

// UpdateMyProfile updates the signed-in admin's mutable profile fields. Only
// non-zero request fields are applied.
func (s *AdminUserService) UpdateMyProfile(req *adminmodel.UpdateMyProfileRequest) (*adminmodel.UpdateMyProfileResponse, error) {
	u, err := s.currentAdmin()
	if err != nil {
		return nil, err
	}
	if req.Nickname != "" {
		u.UserName = req.Nickname
	}
	if req.Avatar != "" {
		u.Avatar = req.Avatar
	}
	if req.BackgroundImage != "" {
		u.BackgroundImage = req.BackgroundImage
	}
	if req.Signature != "" {
		u.Signature = req.Signature
	}
	if err := db.UpdateAdminUserProfile(u); err != nil {
		return nil, err
	}
	return &adminmodel.UpdateMyProfileResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Profile: toAdminAccount(u),
	}, nil
}

// UploadMyAvatar stores the multipart "avatar" image of the current request as
// the signed-in admin's avatar. The account comes from the admin token, so an
// admin can only ever replace their own avatar.
func (s *AdminUserService) UploadMyAvatar(_ *adminmodel.GetMyProfileRequest) (*adminmodel.UpdateMyProfileResponse, error) {
	u, err := s.currentAdmin()
	if err != nil {
		return nil, err
	}
	ref, remove, err := utils.StoreAvatarUpload(s.ctx, s.c, fmt.Sprintf("admin-avatar-%d", u.ID))
	if err != nil {
		return nil, err
	}
	if err := db.UpdateAdminUserAvatar(u.ID, ref); err != nil {
		// Only remove this newly uploaded object; existing avatars may still be referenced.
		remove()
		return nil, err
	}
	u.Avatar = ref
	return &adminmodel.UpdateMyProfileResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Profile: toAdminAccount(u),
	}, nil
}

// GetMySettings returns the signed-in admin's preference key/value map.
func (s *AdminUserService) GetMySettings(req *adminmodel.GetMySettingsRequest) (*adminmodel.GetMySettingsResponse, error) {
	u, err := s.currentAdmin()
	if err != nil {
		return nil, err
	}
	settings, err := decodeSettings(u.Settings)
	if err != nil {
		return nil, err
	}
	return &adminmodel.GetMySettingsResponse{
		Code:     errno.SuccessCode,
		Message:  errno.SuccessMsg,
		Settings: settings,
	}, nil
}

// UpdateMySettings replaces the signed-in admin's preference map.
func (s *AdminUserService) UpdateMySettings(req *adminmodel.UpdateMySettingsRequest) (*adminmodel.UpdateMySettingsResponse, error) {
	u, err := s.currentAdmin()
	if err != nil {
		return nil, err
	}
	settings := req.Settings
	if settings == nil {
		settings = map[string]string{}
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	if err := db.UpdateAdminUserSettings(u.ID, datatypes.JSON(raw)); err != nil {
		return nil, err
	}
	return &adminmodel.UpdateMySettingsResponse{
		Code:     errno.SuccessCode,
		Message:  errno.SuccessMsg,
		Settings: settings,
	}, nil
}

// currentAdmin resolves the signed-in platform account from the token context
// (AdminSessionAuth sets CtxKeyUserID to the admin id).
func (s *AdminUserService) currentAdmin() (*db.AdminUser, error) {
	v, ok := s.c.Get(jwt.CtxKeyUserID)
	if !ok {
		return nil, errno.AuthorizationFailedErr
	}
	id, ok := v.(int64)
	if !ok || id == 0 {
		return nil, errno.AuthorizationFailedErr
	}
	return db.QueryAdminUserByID(id)
}

// decodeSettings parses a stored settings JSON blob into a string map. Empty
// storage yields an empty map so clients never see null.
func decodeSettings(raw datatypes.JSON) (map[string]string, error) {
	if len(raw) == 0 {
		return map[string]string{}, nil
	}
	var settings map[string]string
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, err
	}
	if settings == nil {
		settings = map[string]string{}
	}
	return settings, nil
}

// toAdminAccount maps a db platform account to the API view. A zero status
// (legacy row) is reported as ENABLED, and a stored avatar reference is
// returned as its public URL.
func toAdminAccount(u *db.AdminUser) *adminmodel.AdminAccount {
	status := common.Status(u.Status)
	if status == common.Status_STATUS_UNKNOWN {
		status = common.Status_STATUS_ENABLED
	}
	var createdAt, updatedAt int64
	if !u.CreatedAt.IsZero() {
		createdAt = u.CreatedAt.Unix()
	}
	if !u.UpdatedAt.IsZero() {
		updatedAt = u.UpdatedAt.Unix()
	}
	return &adminmodel.AdminAccount{
		Id:              u.ID,
		Email:           u.Email,
		Nickname:        u.UserName,
		Avatar:          utils.AvatarURL(u.Avatar),
		BackgroundImage: u.BackgroundImage,
		Signature:       u.Signature,
		Status:          status,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}
}
