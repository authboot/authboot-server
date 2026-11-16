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
	"gorm.io/gorm"

	"github.com/authboot/authboot-server/pkg/errno"
)

const userIdentityTableName = "tb_user_identities"

// UserIdentity maps a login identity (type+value) to an app User within an
// organization. One user can own several identities (username / email / phone /
// wechat_openid ...), so a single account can be reached through any login
// method. The (organization_id, identity_type, identity_value) tuple is unique.
type UserIdentity struct {
	ID             int64  `json:"id" gorm:"primaryKey;autoIncrement"`
	OrganizationID int64  `json:"organization_id" gorm:"column:organization_id;not null;uniqueIndex:uk_org_type_value,priority:1"`
	UserID         int64  `json:"user_id" gorm:"column:user_id;not null;index"`
	IdentityType   string `json:"identity_type" gorm:"column:identity_type;type:varchar(32);not null;uniqueIndex:uk_org_type_value,priority:2"`
	IdentityValue  string `json:"identity_value" gorm:"column:identity_value;type:varchar(255);not null;uniqueIndex:uk_org_type_value,priority:3"`
	CreatedAt      int64  `json:"created_at" gorm:"column:created_at"`
	UpdatedAt      int64  `json:"updated_at" gorm:"column:updated_at"`
}

func (UserIdentity) TableName() string {
	return userIdentityTableName
}

// UserIdentityDAO is the data-access handle for the user_identities table. Like
// UserDAO it wraps a *gorm.DB so the same methods run on the global connection
// (via the package default instance Identities) or inside a transaction
// (via WithTx).
type UserIdentityDAO struct {
	db *gorm.DB
}

// NewUserIdentityDAO builds a UserIdentityDAO bound to the given connection.
func NewUserIdentityDAO(db *gorm.DB) *UserIdentityDAO {
	return &UserIdentityDAO{db: db}
}

// WithTx returns a UserIdentityDAO that runs its queries on the given
// transaction, so identity writes can share a tx with the owning user insert.
func (d *UserIdentityDAO) WithTx(tx *gorm.DB) *UserIdentityDAO {
	return &UserIdentityDAO{db: tx}
}

// QueryIdentity looks up a single identity within an organization. A missing
// row is reported as errno.UserIsNotExistErr so callers can distinguish "no
// such account" from a real database error.
func (d *UserIdentityDAO) QueryIdentity(organizationID int64, identityType, identityValue string) (*UserIdentity, error) {
	var identity UserIdentity
	if err := d.db.Where(
		"organization_id = ? AND identity_type = ? AND identity_value = ?",
		organizationID, identityType, identityValue,
	).First(&identity).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errno.UserIsNotExistErr
		}
		return nil, err
	}
	return &identity, nil
}

// CreateIdentity inserts a new identity row and returns its id.
func (d *UserIdentityDAO) CreateIdentity(identity *UserIdentity) (int64, error) {
	if err := d.db.Create(identity).Error; err != nil {
		return 0, err
	}
	return identity.ID, nil
}

// CheckIdentityExist reports whether an identity already exists in the given
// organization, used to reject duplicate registrations.
func (d *UserIdentityDAO) CheckIdentityExist(organizationID int64, identityType, identityValue string) (bool, error) {
	var count int64
	if err := d.db.Model(&UserIdentity{}).Where(
		"organization_id = ? AND identity_type = ? AND identity_value = ?",
		organizationID, identityType, identityValue,
	).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// ListIdentitiesByUserInOrg returns every identity bound to a user within an
// organization, used by account merge to find a contact (phone/email) to verify
// ownership of the account being merged away.
func (d *UserIdentityDAO) ListIdentitiesByUserInOrg(organizationID, userID int64) ([]*UserIdentity, error) {
	var identities []*UserIdentity
	if err := d.db.Where("organization_id = ? AND user_id = ?", organizationID, userID).
		Order("id asc").Find(&identities).Error; err != nil {
		return nil, err
	}
	return identities, nil
}

// ListIdentitiesByUserIDs returns the identities of multiple users within an
// organization in one query (used by dashboard-style lists to avoid N+1).
func (d *UserIdentityDAO) ListIdentitiesByUserIDs(organizationID int64, userIDs []int64) ([]*UserIdentity, error) {
	if len(userIDs) == 0 {
		return []*UserIdentity{}, nil
	}
	var identities []*UserIdentity
	if err := d.db.Where("organization_id = ? AND user_id IN ?", organizationID, userIDs).
		Order("id asc").Find(&identities).Error; err != nil {
		return nil, err
	}
	return identities, nil
}

// DeleteIdentities removes identity rows of a user within an organization,
// optionally narrowed by identity type and/or value. It returns the number of
// rows removed, used by the unbind flow to keep the "last identity" guard.
func (d *UserIdentityDAO) DeleteIdentities(organizationID, userID int64, identityType, identityValue string) (int64, error) {
	q := d.db.Where("organization_id = ? AND user_id = ?", organizationID, userID)
	if identityType != "" {
		q = q.Where("identity_type = ?", identityType)
	}
	if identityValue != "" {
		q = q.Where("identity_value = ?", identityValue)
	}
	res := q.Delete(&UserIdentity{})
	return res.RowsAffected, res.Error
}
