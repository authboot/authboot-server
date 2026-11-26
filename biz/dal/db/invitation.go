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

const organizationInvitationTableName = "tb_organization_invitation"

// invitation status values (mirror invitation.InvitationStatus).
const (
	InvitationStatusPending  = 1
	InvitationStatusAccepted = 2
	InvitationStatusExpired  = 3
	InvitationStatusRevoked  = 4
)

// OrganizationInvitation is a pending/consumed invite binding an email to an
// organization. Token is kept server-side (not exposed via the API model).
type OrganizationInvitation struct {
	ID                int64  `json:"id" gorm:"primaryKey;autoIncrement"`
	OrganizationID    int64  `json:"organization_id" gorm:"column:organization_id;not null;index"`
	Email             string `json:"email" gorm:"type:varchar(255);not null;index"`
	InviterAccountID  int64  `json:"inviter_account_id" gorm:"column:inviter_account_id"`
	Token             string `json:"token" gorm:"type:varchar(64);not null;uniqueIndex"`
	Status            int8   `json:"status" gorm:"column:status;not null;default:1;index"`
	ExpiredAt         int64  `json:"expired_at" gorm:"column:expired_at;not null"`
	AcceptedAccountID int64  `json:"accepted_account_id" gorm:"column:accepted_account_id;not null;default:0"`
	CreatedAt         int64  `json:"created_at" gorm:"column:created_at;not null"`
	UpdatedAt         int64  `json:"updated_at" gorm:"column:updated_at;not null"`
}

// TableName set table name to make gorm can correctly identify
func (OrganizationInvitation) TableName() string {
	return organizationInvitationTableName
}

// OrganizationInvitationDAO is the data-access handle for the organization
// invitation table. It wraps a *gorm.DB so the same methods run on the global
// connection (via the package default instance IOrganizationInvitationDAO) or
// inside a transaction (via WithTx).
type OrganizationInvitationDAO struct {
	db *gorm.DB
}

// NewOrganizationInvitationDAO builds an OrganizationInvitationDAO bound to the given connection.
func NewOrganizationInvitationDAO(db *gorm.DB) *OrganizationInvitationDAO {
	return &OrganizationInvitationDAO{db: db}
}

// WithTx returns an OrganizationInvitationDAO that runs its queries on the given transaction.
func (d *OrganizationInvitationDAO) WithTx(tx *gorm.DB) *OrganizationInvitationDAO {
	return &OrganizationInvitationDAO{db: tx}
}

// CreateInvitation inserts a new invitation and returns its id.
func (d *OrganizationInvitationDAO) CreateInvitation(inv *OrganizationInvitation) (int64, error) {
	if err := d.db.Create(inv).Error; err != nil {
		return 0, err
	}
	return inv.ID, nil
}

// QueryInvitationByID returns an invitation by id, or InvitationNotExistErr.
func (d *OrganizationInvitationDAO) QueryInvitationByID(id int64) (*OrganizationInvitation, error) {
	var inv OrganizationInvitation
	if err := d.db.Where("id = ?", id).Find(&inv).Error; err != nil {
		return nil, err
	}
	if inv.ID == 0 {
		return nil, errno.InvitationNotExistErr
	}
	return &inv, nil
}

// QueryInvitationByToken returns an invitation by its token, or
// InvitationNotExistErr when no invitation carries the token.
func (d *OrganizationInvitationDAO) QueryInvitationByToken(token string) (*OrganizationInvitation, error) {
	var inv OrganizationInvitation
	if err := d.db.Where("token = ?", token).Find(&inv).Error; err != nil {
		return nil, err
	}
	if inv.ID == 0 {
		return nil, errno.InvitationNotExistErr
	}
	return &inv, nil
}

// ListInvitationsByOrg returns a page of an organization's invitations
// (newest first) plus the total count.
func (d *OrganizationInvitationDAO) ListInvitationsByOrg(organizationID int64, page, pageSize int) ([]*OrganizationInvitation, int64, error) {
	return d.ListInvitationsByOrgFiltered(organizationID, "", 0, page, pageSize)
}

// ListInvitationsByOrgFiltered pages an organization's invitations, newest
// first, optionally matching the email (LIKE) and a status (0 = all).
func (d *OrganizationInvitationDAO) ListInvitationsByOrgFiltered(organizationID int64, search string, status int, page, pageSize int) ([]*OrganizationInvitation, int64, error) {
	base := func() *gorm.DB {
		q := d.db.Model(&OrganizationInvitation{}).Where("organization_id = ?", organizationID)
		if search != "" {
			q = q.Where("email LIKE ?", "%"+search+"%")
		}
		if status != 0 {
			q = q.Where("status = ?", status)
		}
		return q
	}

	var total int64
	if err := base().Count(&total).Error; err != nil {
		return nil, 0, err
	}

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}

	var list []*OrganizationInvitation
	if err := base().Order("id desc").
		Offset((page - 1) * pageSize).Limit(pageSize).
		Find(&list).Error; err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// UpdateInvitationStatus sets the status of an invitation.
func (d *OrganizationInvitationDAO) UpdateInvitationStatus(id int64, status int, updatedAt int64) error {
	return d.db.Model(&OrganizationInvitation{}).Where("id = ?", id).
		Updates(map[string]interface{}{"status": status, "updated_at": updatedAt}).Error
}

// RenewInvitation replaces the token and expiry of a pending invitation so it
// can be re-sent without creating a second row for the same email.
func (d *OrganizationInvitationDAO) RenewInvitation(id int64, token string, expiredAt, updatedAt int64) error {
	return d.db.Model(&OrganizationInvitation{}).Where("id = ? AND status = ?", id, InvitationStatusPending).
		Updates(map[string]interface{}{"token": token, "expired_at": expiredAt, "updated_at": updatedAt}).Error
}

// AcceptInvitationRecord marks an invitation accepted by an account.
func (d *OrganizationInvitationDAO) AcceptInvitationRecord(id, acceptedAccountID, updatedAt int64) error {
	return d.db.Model(&OrganizationInvitation{}).Where("id = ?", id).
		Updates(map[string]interface{}{
			"status":              InvitationStatusAccepted,
			"accepted_account_id": acceptedAccountID,
			"updated_at":          updatedAt,
		}).Error
}
