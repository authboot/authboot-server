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
	"time"

	"gorm.io/gorm"

	"github.com/authboot/authboot-server/biz/model/membership"
	"github.com/authboot/authboot-server/pkg/errno"
)

const organizationMembershipTableName = "tb_organization_membership"

// MembershipActive matches the membership protocol status, not the generic enabled status.
const MembershipActive int8 = int8(membership.MembershipStatus_MEMBERSHIP_STATUS_ACTIVE)

// OrganizationMembership is the join record binding a platform account to an
// organization. Mirrors biz/model/membership.OrganizationMembership.
type OrganizationMembership struct {
	ID             int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	OrganizationID int64     `json:"organization_id" gorm:"column:organization_id;not null;uniqueIndex:uk_org_account;index:idx_membership_org_status,priority:1"`
	AccountID      int64     `json:"account_id" gorm:"column:account_id;not null;uniqueIndex:uk_org_account"`
	Status         int8      `json:"status" gorm:"type:tinyint;not null;default:1;index;index:idx_membership_org_status,priority:2"`
	Role           string    `json:"role" gorm:"type:varchar(16);not null;default:member"`
	CreatedAt      time.Time `json:"created_at" gorm:"not null"`
	UpdatedAt      time.Time `json:"updated_at" gorm:"not null"`
}

// TableName set table name to make gorm can correctly identify
func (OrganizationMembership) TableName() string {
	return organizationMembershipTableName
}

// OrganizationMembershipDAO is the data-access handle for the organization
// membership table. It wraps a *gorm.DB so the same methods run on the global
// connection (via the package default instance IOrganizationMembershipDAO) or
// inside a transaction (via WithTx).
type OrganizationMembershipDAO struct {
	db *gorm.DB
}

// NewOrganizationMembershipDAO builds an OrganizationMembershipDAO bound to the given connection.
func NewOrganizationMembershipDAO(db *gorm.DB) *OrganizationMembershipDAO {
	return &OrganizationMembershipDAO{db: db}
}

// WithTx returns an OrganizationMembershipDAO that runs its queries on the given transaction.
func (d *OrganizationMembershipDAO) WithTx(tx *gorm.DB) *OrganizationMembershipDAO {
	return &OrganizationMembershipDAO{db: tx}
}

// QueryMembership returns an account's membership record in an organization,
// or MembershipNotExistErr when the account is not a member.
func (d *OrganizationMembershipDAO) QueryMembership(organizationID, accountID int64) (*OrganizationMembership, error) {
	var m OrganizationMembership
	if err := d.db.Where("organization_id = ? AND account_id = ?", organizationID, accountID).Find(&m).Error; err != nil {
		return nil, err
	}
	if m.ID == 0 {
		return nil, errno.MembershipNotExistErr
	}
	return &m, nil
}

// CreateMembership inserts a new membership row and returns its id.
func (d *OrganizationMembershipDAO) CreateMembership(m *OrganizationMembership) (int64, error) {
	if err := d.db.Create(m).Error; err != nil {
		return 0, err
	}
	return m.ID, nil
}

// LeaveOrganization removes an account's membership in an organization. It
// returns MembershipNotExistErr when the account was not a member.
func (d *OrganizationMembershipDAO) LeaveOrganization(organizationID, accountID int64) error {
	result := d.db.Where("organization_id = ? AND account_id = ?", organizationID, accountID).
		Delete(&OrganizationMembership{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errno.MembershipNotExistErr
	}
	return nil
}
