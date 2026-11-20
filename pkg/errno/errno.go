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

package errno

import (
	"errors"
	"fmt"
)

const (
	SuccessCode    = 0
	ServiceErrCode = iota + 10000
	ParamErrCode
	AuthorizationFailedErrCode

	UserAlreadyExistErrCode
	UserIsNotExistErrCode

	FollowRelationAlreadyExistErrCode
	FollowRelationNotExistErrCode

	FavoriteRelationAlreadyExistErrCode
	FavoriteRelationNotExistErrCode
	FavoriteActionErrCode

	MessageAddFailedErrCode
	FriendListNoPermissionErrCode

	VideoIsNotExistErrCode
	CommentIsNotExistErrCode

	// authboot multi-tenant platform error codes
	OrganizationNotExistErrCode
	OrganizationDisabledErrCode
	OrganizationAlreadyExistErrCode
	PlatformAccountNotExistErrCode
	PlatformAccountAlreadyExistErrCode
	MembershipNotExistErrCode
	PermissionDeniedErrCode
	InvitationNotExistErrCode
	InvitationInvalidErrCode
	IdentityAlreadyExistErrCode
	CrossOrganizationAccessErrCode

	// notification error codes
	NotificationNotExistErrCode

	// user address error codes
	UserAddressNotExistErrCode
	UserAddressLimitErrCode

	// Retired error codes; preserve subsequent public code values.
	_
	_
	_
	_
	_

	// identity binding error codes
	IdentityLastOneErrCode

	// password error codes
	PasswordNotSetErrCode

	// client management error codes
	ClientNotExistErrCode

	// organization settings error codes
	LoginMethodDisabledErrCode
)

const (
	SuccessMsg               = "Success"
	ServerErrMsg             = "Service is unable to start successfully"
	ParamErrMsg              = "Wrong Parameter has been given"
	UserIsNotExistErrMsg     = "user is not exist"
	PasswordIsNotVerifiedMsg = "username or password not verified"
	FavoriteActionErrMsg     = "favorite add failed"

	MessageAddFailedErrMsg    = "message add failed"
	FriendListNoPermissionMsg = "You can't query his friend list"
	VideoIsNotExistErrMsg     = "video is not exist"
	CommentIsNotExistErrMsg   = "comment is not exist"
)

type ErrNo struct {
	ErrCode int32
	ErrMsg  string
}

func (e ErrNo) Error() string {
	return fmt.Sprintf("err_code=%d, err_msg=%s", e.ErrCode, e.ErrMsg)
}

func NewErrNo(code int32, msg string) ErrNo {
	return ErrNo{code, msg}
}

func (e ErrNo) WithMessage(msg string) ErrNo {
	e.ErrMsg = msg
	return e
}

var (
	Success                         = NewErrNo(SuccessCode, SuccessMsg)
	ServiceErr                      = NewErrNo(ServiceErrCode, ServerErrMsg)
	ParamErr                        = NewErrNo(ParamErrCode, ParamErrMsg)
	UserAlreadyExistErr             = NewErrNo(UserAlreadyExistErrCode, "User already exists")
	AuthorizationFailedErr          = NewErrNo(AuthorizationFailedErrCode, "Authorization failed")
	UserIsNotExistErr               = NewErrNo(UserIsNotExistErrCode, UserIsNotExistErrMsg)
	PasswordIsNotVerified           = NewErrNo(AuthorizationFailedErrCode, PasswordIsNotVerifiedMsg)
	FollowRelationAlreadyExistErr   = NewErrNo(FollowRelationAlreadyExistErrCode, "Follow Relation already exist")
	FollowRelationNotExistErr       = NewErrNo(FollowRelationNotExistErrCode, "Follow Relation does not exist")
	FavoriteRelationAlreadyExistErr = NewErrNo(FavoriteRelationAlreadyExistErrCode, "Favorite Relation already exist")
	FavoriteRelationNotExistErr     = NewErrNo(FavoriteRelationNotExistErrCode, "FavoriteRelationNotExistErr")
	FavoriteActionErr               = NewErrNo(FavoriteActionErrCode, FavoriteActionErrMsg)

	MessageAddFailedErr       = NewErrNo(MessageAddFailedErrCode, MessageAddFailedErrMsg)
	FriendListNoPermissionErr = NewErrNo(FriendListNoPermissionErrCode, FriendListNoPermissionMsg)
	VideoIsNotExistErr        = NewErrNo(VideoIsNotExistErrCode, VideoIsNotExistErrMsg)
	CommentIsNotExistErr      = NewErrNo(CommentIsNotExistErrCode, CommentIsNotExistErrMsg)

	// authboot multi-tenant platform errors
	OrganizationNotExistErr        = NewErrNo(OrganizationNotExistErrCode, "organization does not exist")
	OrganizationDisabledErr        = NewErrNo(OrganizationDisabledErrCode, "organization is disabled")
	OrganizationAlreadyExistErr    = NewErrNo(OrganizationAlreadyExistErrCode, "organization code already exists")
	PlatformAccountNotExistErr     = NewErrNo(PlatformAccountNotExistErrCode, "platform account does not exist")
	PlatformAccountAlreadyExistErr = NewErrNo(PlatformAccountAlreadyExistErrCode, "platform account already exists")
	MembershipNotExistErr          = NewErrNo(MembershipNotExistErrCode, "you are not a member of this organization")
	PermissionDeniedErr            = NewErrNo(PermissionDeniedErrCode, "permission denied")
	InvitationNotExistErr          = NewErrNo(InvitationNotExistErrCode, "invitation does not exist")
	InvitationInvalidErr           = NewErrNo(InvitationInvalidErrCode, "invitation is invalid or expired")
	IdentityAlreadyExistErr        = NewErrNo(IdentityAlreadyExistErrCode, "identity already exists in this organization")
	CrossOrganizationAccessErr     = NewErrNo(CrossOrganizationAccessErrCode, "cross-organization access is not allowed")

	// notification errors
	NotificationNotExistErr = NewErrNo(NotificationNotExistErrCode, "notification does not exist")

	// user address errors
	UserAddressNotExistErr = NewErrNo(UserAddressNotExistErrCode, "address does not exist")
	UserAddressLimitErr    = NewErrNo(UserAddressLimitErrCode, "address limit reached (max 10)")

	// identity binding errors
	IdentityLastOneErr = NewErrNo(IdentityLastOneErrCode, "cannot unbind the last login identity")

	// password errors
	PasswordNotSetErr = NewErrNo(PasswordNotSetErrCode, "password is not set for this account; use password reset")

	// client management errors
	ClientNotExistErr = NewErrNo(ClientNotExistErrCode, "client does not exist")

	// organization settings errors
	LoginMethodDisabledErr = NewErrNo(LoginMethodDisabledErrCode, "this sign-in method is disabled by the organization")
)

// ConvertErr convert error to Errno
func ConvertErr(err error) ErrNo {
	Err := ErrNo{}
	if errors.As(err, &Err) {
		return Err
	}

	s := ServiceErr
	s.ErrMsg = err.Error()
	return s
}
