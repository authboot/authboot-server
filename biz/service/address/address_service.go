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

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/authboot/authboot-server/biz/dal/db"
	address "github.com/authboot/authboot-server/biz/model/address"
	"github.com/authboot/authboot-server/pkg/errno"
)

type AddressService struct {
	ctx context.Context
	c   *app.RequestContext
}

// NewAddressService creates an address-book service for the authenticated user.
func NewAddressService(ctx context.Context, c *app.RequestContext) *AddressService {
	return &AddressService{ctx: ctx, c: c}
}

// currentUser reads the authenticated org user id and its organization from the
// context set by UserSessionAuth. Ownership always comes from here, never from
// the request body.
func (s *AddressService) currentUser() (orgID, userID int64, err error) {
	uv, ok := s.c.Get("current_user_id")
	if !ok {
		return 0, 0, errno.AuthorizationFailedErr
	}
	userID, ok = uv.(int64)
	if !ok {
		return 0, 0, errno.AuthorizationFailedErr
	}
	if ov, ok := s.c.Get("organization_id"); ok {
		orgID, _ = ov.(int64)
	}
	return orgID, userID, nil
}

// ListAddresses returns the current user's address book (default first).
func (s *AddressService) ListAddresses() ([]*db.UserAddress, error) {
	_, userID, err := s.currentUser()
	if err != nil {
		return nil, err
	}
	return db.ListUserAddresses(userID)
}

// CreateAddress adds an address for the current user. OrganizationID/UserID are
// taken from the auth context; the per-user cap of 10 is enforced in the dal.
func (s *AddressService) CreateAddress(addr *db.UserAddress) (*db.UserAddress, error) {
	orgID, userID, err := s.currentUser()
	if err != nil {
		return nil, err
	}
	addr.ID = 0
	addr.OrganizationID = orgID
	addr.UserID = userID
	if err := db.CreateUserAddress(addr); err != nil {
		return nil, err
	}
	return addr, nil
}

// UpdateAddress updates one of the current user's addresses. UserID is forced
// from the auth context so a caller cannot edit another user's address.
func (s *AddressService) UpdateAddress(addr *db.UserAddress) (*db.UserAddress, error) {
	_, userID, err := s.currentUser()
	if err != nil {
		return nil, err
	}
	addr.UserID = userID
	if err := db.UpdateUserAddress(addr); err != nil {
		return nil, err
	}
	return addr, nil
}

// DeleteAddress removes one of the current user's addresses.
func (s *AddressService) DeleteAddress(addressID int64) error {
	_, userID, err := s.currentUser()
	if err != nil {
		return err
	}
	return db.DeleteUserAddress(userID, addressID)
}

// SetDefaultAddress marks one of the current user's addresses as the default.
func (s *AddressService) SetDefaultAddress(addressID int64) error {
	_, userID, err := s.currentUser()
	if err != nil {
		return err
	}
	return db.SetDefaultUserAddress(userID, addressID)
}

// ---------------------------------------------------------------------------
// Admin (management) side: an admin edits a user's address book. Ownership
// comes from the path (organization_id, user_id); the user must belong to the
// organization or every call fails with UserIsNotExistErr.
// ---------------------------------------------------------------------------

// AdminAddressService manages one organization user's address book.
type AdminAddressService struct {
	ctx    context.Context
	c      *app.RequestContext
	orgID  int64
	userID int64
}

// NewAdminAddressService resolves the target user and checks it belongs to the
// organization in the path.
func NewAdminAddressService(ctx context.Context, c *app.RequestContext, orgID, userID int64) (*AdminAddressService, error) {
	if orgID <= 0 || userID <= 0 {
		return nil, errno.ParamErr
	}
	u, err := db.IUserDAO.QueryUserById(userID)
	if err != nil {
		return nil, err
	}
	if u.OrganizationID != orgID {
		return nil, errno.UserIsNotExistErr
	}
	return &AdminAddressService{ctx: ctx, c: c, orgID: orgID, userID: userID}, nil
}

// List returns the user's address book, default first.
func (s *AdminAddressService) List() ([]*db.UserAddress, error) {
	return db.ListUserAddressesInOrg(s.orgID, s.userID)
}

// Create adds an address for the user; the 10-address cap and first-is-default
// rule are enforced in the dal.
func (s *AdminAddressService) Create(addr *db.UserAddress) (*db.UserAddress, error) {
	addr.ID = 0
	addr.OrganizationID = s.orgID
	addr.UserID = s.userID
	if err := db.CreateUserAddress(addr); err != nil {
		return nil, err
	}
	return addr, nil
}

// Update replaces the editable fields of one address.
func (s *AdminAddressService) Update(addr *db.UserAddress) (*db.UserAddress, error) {
	addr.OrganizationID = s.orgID
	addr.UserID = s.userID
	if err := db.UpdateUserAddress(addr); err != nil {
		return nil, err
	}
	return addr, nil
}

// Delete removes one address; if it was the default the newest remaining one
// becomes default.
func (s *AdminAddressService) Delete(addressID int64) error {
	return db.DeleteUserAddress(s.userID, addressID)
}

// SetDefault marks one address as the default.
func (s *AdminAddressService) SetDefault(addressID int64) error {
	return db.SetDefaultUserAddress(s.userID, addressID)
}

// ToAPI converts a stored address to the API shape (unix-second timestamps).
func ToAPI(a *db.UserAddress) *address.UserAddress {
	return &address.UserAddress{
		Id:            a.ID,
		ReceiverName:  a.ReceiverName,
		ReceiverPhone: a.ReceiverPhone,
		Province:      a.Province,
		City:          a.City,
		District:      a.District,
		Detail:        a.Detail,
		IsDefault:     a.IsDefault,
		CreatedAt:     a.CreatedAt.Unix(),
		UpdatedAt:     a.UpdatedAt.Unix(),
	}
}

// ToAPIList converts a slice of stored addresses.
func ToAPIList(list []*db.UserAddress) []*address.UserAddress {
	out := make([]*address.UserAddress, 0, len(list))
	for _, a := range list {
		out = append(out, ToAPI(a))
	}
	return out
}
