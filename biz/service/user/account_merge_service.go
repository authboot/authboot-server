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

// Account merging (self-service, App users only): a logged-in user absorbs a
// second account (its identities and business data) into their own. The user
// must prove ownership of the target account by a verification code sent to its
// bound phone/email, so an account can never be stolen by someone who merely
// knows its id. Platform admins live in a separate table and are never part of
// this flow.
package user

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"gorm.io/gorm"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/model/user"
	"github.com/authboot/authboot-server/biz/mw/email"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/biz/mw/sms"
	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
)

// mergeCodeStore is the redis-backed one-time code store for account merge.
// The scene ("merge") namespaces codes so they never collide with login/register
// codes; the target's contact (phone or email) is the key, exactly like the
// auth service's code flows.
var mergeCodeStore redis.Code

// mergeSessionStore revokes every session of both accounts once the merge
// commits, forcing the client to re-login as the merged (surviving) account.
var mergeSessionStore redis.SessionStore

const (
	// mergeCodeScene namespaces merge verification codes in redis.
	mergeCodeScene = "merge"
	// mergeCodeTTL is how long a merge verification code stays valid.
	mergeCodeTTL = 5 * time.Minute
	// mergeCodeRetryAfterSeconds is the suggested client cool-down before resend.
	mergeCodeRetryAfterSeconds = 60
)

// AccountService handles end-user account self-service operations. Unlike the
// admin UserService, the acting user is taken from the authenticated token, not
// from the request body — a user can only ever merge another account INTO their
// own.
type AccountService struct {
	ctx context.Context
	c   *app.RequestContext

	userDAO         *db.UserDAO
	userIdentityDAO *db.UserIdentityDAO
}

// NewAccountService creates an account self-service service.
func NewAccountService(ctx context.Context, c *app.RequestContext) *AccountService {
	return &AccountService{
		ctx:             ctx,
		c:               c,
		userDAO:         db.NewUserDAO(db.DB),
		userIdentityDAO: db.NewUserIdentityDAO(db.DB),
	}
}

// PrepareMerge starts an account merge: it locates the target account's bound
// phone/email, sends a one-time verification code to it, and returns a masked
// contact so the caller can confirm where the code went. Nothing is changed
// yet — the actual merge happens on MergeAccount.
func (s *AccountService) PrepareMerge(req *user.PrepareMergeRequest) (*user.PrepareMergeResponse, error) {
	if req.AccountId == 0 {
		return nil, errno.ParamErr
	}
	survivor, err := s.currentUser()
	if err != nil {
		return nil, err
	}
	if err := s.checkMergeable(survivor, req.AccountId); err != nil {
		return nil, err
	}
	target, err := s.userDAO.QueryUserByIdInOrg(survivor.OrganizationID, req.AccountId)
	if err != nil {
		return nil, err
	}
	contact, channel, err := s.targetContact(target)
	if err != nil {
		return nil, err
	}

	code, err := newMergeCode()
	if err != nil {
		return nil, err
	}
	if err := mergeCodeStore.Store(mergeCodeScene, contact, code, mergeCodeTTL); err != nil {
		return nil, err
	}
	body := fmt.Sprintf("你的账号合并验证码是 %s，%d 分钟内有效。", code, int(mergeCodeTTL/time.Minute))
	switch channel {
	case contactChannelEmail:
		if err := email.Send(s.ctx, &email.Message{
			To:      []string{contact},
			Subject: "账号合并验证码",
			Text:    body,
		}); err != nil {
			return nil, err
		}
	case contactChannelSMS:
		if err := sms.Send(s.ctx, &sms.Message{
			PhoneNumbers:  []string{contact},
			TemplateParam: map[string]string{"code": code},
			Content:       body,
		}); err != nil {
			return nil, err
		}
	}

	return &user.PrepareMergeResponse{
		Code:              errno.SuccessCode,
		Message:           errno.SuccessMsg,
		MaskedContact:     maskContact(contact),
		ExpireSeconds:     int32(mergeCodeTTL / time.Second),
		RetryAfterSeconds: mergeCodeRetryAfterSeconds,
	}, nil
}

// MergeAccount completes a merge after ownership of the target account is
// proven by the verification code. In one transaction it moves the target's
// identities and business data onto the survivor, backfills empty profile
// fields, and tombstones the target row; afterwards every session of both
// accounts is revoked so clients must re-login as the merged account.
func (s *AccountService) MergeAccount(req *user.MergeAccountRequest) (*user.MergeAccountResponse, error) {
	if req.AccountId == 0 || req.Code == "" {
		return nil, errno.ParamErr
	}
	survivor, err := s.currentUser()
	if err != nil {
		return nil, err
	}
	if err := s.checkMergeable(survivor, req.AccountId); err != nil {
		return nil, err
	}
	target, err := s.userDAO.QueryUserByIdInOrg(survivor.OrganizationID, req.AccountId)
	if err != nil {
		return nil, err
	}
	// Ownership check: the code was sent to the target's contact; verify it
	// against the CURRENT contact in case the identity changed since Prepare.
	contact, _, err := s.targetContact(target)
	if err != nil {
		return nil, err
	}
	if !mergeCodeStore.Verify(mergeCodeScene, contact, req.Code) {
		return nil, errno.AccountMergeCodeInvalidErr
	}

	// Carry the device identity of the session being replaced into the fresh
	// token re-issued below.
	deviceID, deviceName := CurrentSessionDevice(s.c)

	if err := MergeUserAccounts(s.ctx, survivor, target); err != nil {
		return nil, err
	}

	// Re-issue a fresh token pair so the current client keeps its session
	// instead of logging in again after the merge revoked everything.
	accessToken, refreshToken, accessExp, refreshExp, err := ReissueTokens(survivor, deviceID, deviceName)
	if err != nil {
		// Re-issue failed (e.g. redis down): the merge still committed; the
		// empty token fields tell the client to fall back to logging in.
		hlog.CtxErrorf(s.ctx, "account merge: reissue survivor %d tokens: %v", survivor.ID, err)
	}

	return &user.MergeAccountResponse{
		Code:                  errno.SuccessCode,
		Message:               errno.SuccessMsg,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: refreshExp,
	}, nil
}

// ReissueTokens opens a fresh server-side session for the user and mints a new
// access/refresh token pair bound to it. Account merge and conflict-driven
// binds call it after revoking every old session, so the current client keeps a
// valid token instead of being forced to log in again. deviceID/deviceName are
// carried over from the session being replaced.
func ReissueTokens(u *db.User, deviceID, deviceName string) (accessToken, refreshToken string, accessExpiresAt, refreshExpiresAt int64, err error) {
	rec, err := mergeSessionStore.Create(jwt.SubjectUser, u.ID, u.OrganizationID, deviceID, deviceName, redis.DefaultSessionTTL)
	if err != nil {
		return "", "", 0, 0, err
	}
	accessToken, accessExp, err := jwt.GenerateUserAccessToken(rec.AccountID, rec.OrganizationID, rec.SessionID)
	if err != nil {
		return "", "", 0, 0, err
	}
	return accessToken, rec.RefreshToken, accessExp, rec.ExpiresAt, nil
}

// CurrentSessionDevice reads the device identity of the request's session (from
// the token context), so a re-issued token can carry the same device identity
// as the session it replaces.
func CurrentSessionDevice(c *app.RequestContext) (deviceID, deviceName string) {
	v, _ := c.Get(jwt.CtxKeySessionID)
	sid, _ := v.(string)
	if sid == "" {
		return "", ""
	}
	rec, err := mergeSessionStore.Get(jwt.SubjectUser, sid)
	if err != nil {
		return "", ""
	}
	return rec.DeviceID, rec.DeviceName
}

// MergeUserAccounts merges target INTO survivor. It is the single source of
// truth for every account merge in the system, shared by the post-hoc
// /api/v1/account/merge endpoints and claim-at-login in the auth service.
//
// Callers must already have proven ownership of BOTH accounts (a contact code
// for one and a login/claim credential for the other); this function only
// re-checks the invariant preconditions, then in one transaction moves the
// target's identities and business data onto the survivor, backfills empty
// profile fields, and disables the target row. Afterwards every session of
// both accounts is revoked so clients must re-login as the merged account.
func MergeUserAccounts(ctx context.Context, survivor, target *db.User) error {
	if target.ID == survivor.ID {
		return errno.AccountMergeSelfErr
	}
	if survivor.OrganizationID != target.OrganizationID {
		return errno.CrossOrganizationAccessErr
	}
	if survivor.Status != constants.StatusEnabled || target.Status != constants.StatusEnabled {
		return errno.AccountMergeNotAllowedErr
	}

	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		// 1. Move the target's identities onto the survivor. The
		//    (organization_id, identity_type, identity_value) unique index
		//    guarantees no duplicate can arise: the same value cannot belong to
		//    two users, so the move is always conflict-free.
		if err := tx.Model(&db.UserIdentity{}).
			Where("organization_id = ? AND user_id = ?", survivor.OrganizationID, target.ID).
			Update("user_id", survivor.ID).Error; err != nil {
			return err
		}
		// 2. Backfill survivor profile fields that are still empty.
		if err := backfillProfile(tx, survivor, target); err != nil {
			return err
		}
		// 3. Repoint business data owned by the target account.
		if err := tx.Model(&db.UserAddress{}).
			Where("organization_id = ? AND user_id = ?", survivor.OrganizationID, target.ID).
			Update("user_id", survivor.ID).Error; err != nil {
			return err
		}
		if err := tx.Model(&db.Notification{}).
			Where("user_id = ?", target.ID).
			Update("user_id", survivor.ID).Error; err != nil {
			return err
		}
		// 4. Disable the target row so it can never log in or be merged again.
		return db.NewUserDAO(tx).SetUserStatus(survivor.OrganizationID, target.ID, constants.StatusDisabled)
	}); err != nil {
		return err
	}

	// Revoke every session of both accounts: the target's are dead by
	// definition, and the survivor's are dropped so the client re-authenticates
	// as the merged account (standard practice after an account change). This is
	// best-effort: the merge has already committed, and if redis is down the
	// session guards fail closed anyway, so reporting failure here would just
	// confuse a client whose merge actually succeeded.
	if err := mergeSessionStore.RevokeAllForUser(jwt.SubjectUser, target.ID); err != nil {
		hlog.CtxErrorf(ctx, "account merge: revoke target %d sessions: %v", target.ID, err)
	}
	if err := mergeSessionStore.RevokeAllForUser(jwt.SubjectUser, survivor.ID); err != nil {
		hlog.CtxErrorf(ctx, "account merge: revoke survivor %d sessions: %v", survivor.ID, err)
	}
	return nil
}

// currentUser resolves the authenticated user from the token context set by
// jwt.UserSessionAuth.
func (s *AccountService) currentUser() (*db.User, error) {
	userID, ok := s.c.Get(jwt.CtxKeyUserID)
	if !ok {
		return nil, errno.AuthorizationFailedErr
	}
	id, ok := userID.(int64)
	if !ok {
		return nil, errno.AuthorizationFailedErr
	}
	orgID, ok := s.c.Get(jwt.CtxKeyOrgID)
	if !ok {
		return nil, errno.AuthorizationFailedErr
	}
	oid, ok := orgID.(int64)
	if !ok {
		return nil, errno.AuthorizationFailedErr
	}
	return s.userDAO.QueryUserByIdInOrg(oid, id)
}

// checkMergeable validates the preconditions shared by PrepareMerge and
// MergeAccount: same organization, no self-merge, both accounts enabled, and
// the target not already merged. State can change between prepare and merge, so
// it is re-checked on both calls.
func (s *AccountService) checkMergeable(survivor *db.User, targetID int64) error {
	if targetID == survivor.ID {
		return errno.AccountMergeSelfErr
	}
	if survivor.Status != constants.StatusEnabled {
		return errno.AccountMergeNotAllowedErr
	}
	target, err := s.userDAO.QueryUserByIdInOrg(survivor.OrganizationID, targetID)
	if err != nil {
		return err
	}
	if target.Status != constants.StatusEnabled {
		return errno.AccountMergeNotAllowedErr
	}
	return nil
}

// targetContact picks the identity whose bound value can receive a verification
// code: email is preferred (stable, globally unique), then phone. An account
// with neither cannot prove ownership and is not mergeable.
func (s *AccountService) targetContact(target *db.User) (contact, channel string, err error) {
	identities, err := s.userIdentityDAO.ListIdentitiesByUserInOrg(target.OrganizationID, target.ID)
	if err != nil {
		return "", "", err
	}
	for _, id := range identities {
		if id.IdentityType == constants.IdentityTypeEmail {
			return id.IdentityValue, contactChannelEmail, nil
		}
	}
	for _, id := range identities {
		if id.IdentityType == constants.IdentityTypePhone {
			return id.IdentityValue, contactChannelSMS, nil
		}
	}
	return "", "", errno.AccountMergeNoContactErr
}

// backfillProfile copies target profile fields into the survivor when the
// survivor's are empty (only non-zero target fields are considered).
func backfillProfile(tx *gorm.DB, survivor, target *db.User) error {
	updates := map[string]interface{}{}
	if survivor.UserName == "" && target.UserName != "" {
		updates["user_name"] = target.UserName
	}
	if survivor.Avatar == "" && target.Avatar != "" {
		updates["avatar"] = target.Avatar
	}
	if survivor.Bio == "" && target.Bio != "" {
		updates["bio"] = target.Bio
	}
	if survivor.Birthday == "" && target.Birthday != "" {
		updates["birthday"] = target.Birthday
	}
	if survivor.Gender == 0 && target.Gender != 0 {
		updates["gender"] = target.Gender
	}
	if len(updates) == 0 {
		return nil
	}
	return tx.Model(&db.User{}).
		Where("id = ? AND organization_id = ?", survivor.ID, survivor.OrganizationID).
		Updates(updates).Error
}

// contact channels used to deliver the merge verification code.
const (
	contactChannelEmail = "email"
	contactChannelSMS   = "sms"
)

// newMergeCode returns a cryptographically random 6-digit code.
func newMergeCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// maskContact hides the middle of a phone number or the local part of an email
// address (al***@example.com), enough to confirm where a code was sent without
// leaking the full contact.
func maskContact(value string) string {
	if i := strings.Index(value, "@"); i > 0 {
		local, domain := value[:i], value[i:]
		if len(local) <= 2 {
			return strings.Repeat("*", len(local)) + domain
		}
		return local[:2] + strings.Repeat("*", len(local)-2) + domain
	}
	r := []rune(value)
	n := len(r)
	if n <= 4 {
		return strings.Repeat("*", n)
	}
	return string(r[:3]) + strings.Repeat("*", n-3)
}
