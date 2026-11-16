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
	"errors"

	"gorm.io/gorm"

	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
)

// AppClient is one product client (iOS / Android / H5 / mini-program...) that
// belongs to an organization. ClientType mirrors common.ClientType.
type AppClient struct {
	ID             int64  `json:"id" gorm:"primaryKey;autoIncrement"`
	OrganizationID int64  `json:"organization_id" gorm:"column:organization_id;not null;index"`
	Name           string `json:"name" gorm:"type:varchar(128);not null"`
	ClientType     int32  `json:"client_type" gorm:"column:client_type;type:int;not null;default:0"`
	Status         int8   `json:"status" gorm:"column:status;type:tinyint;not null;default:1;index"`
	CreatedAt      int64  `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt      int64  `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
}

// TableName defines the table name for the AppClient struct.
func (AppClient) TableName() string { return constants.AppClientTableName }

// AppClientDAO is the data-access handle for the client table. It wraps a
// *gorm.DB so the same methods run on the global connection (via the package
// default instance) or inside a transaction (via WithTx).
type AppClientDAO struct {
	db *gorm.DB
}

// NewAppClientDAO builds an AppClientDAO bound to the given connection.
func NewAppClientDAO(db *gorm.DB) *AppClientDAO {
	return &AppClientDAO{db: db}
}

// WithTx returns an AppClientDAO that runs its queries on the given transaction.
func (d *AppClientDAO) WithTx(tx *gorm.DB) *AppClientDAO {
	return &AppClientDAO{db: tx}
}

// Create inserts a client and returns its id.
func (d *AppClientDAO) Create(c *AppClient) (int64, error) {
	if c.Status == 0 {
		c.Status = constants.StatusEnabled
	}
	if err := d.db.Create(c).Error; err != nil {
		return 0, err
	}
	return c.ID, nil
}

// QueryByIDInOrg returns a client by id, scoped to its organization.
func (d *AppClientDAO) QueryByIDInOrg(organizationID, clientID int64) (*AppClient, error) {
	var c AppClient
	if err := d.db.Where("id = ? AND organization_id = ?", clientID, organizationID).
		First(&c).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errno.ClientNotExistErr
		}
		return nil, err
	}
	return &c, nil
}

// ListByOrg returns a page of an organization's clients plus the total count.
func (d *AppClientDAO) ListByOrg(organizationID int64, offset, limit int) ([]*AppClient, int64, error) {
	var (
		clients []*AppClient
		total   int64
	)
	q := d.db.Model(&AppClient{}).Where("organization_id = ?", organizationID)
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := q.Order("id asc").Offset(offset).Limit(limit).Find(&clients).Error; err != nil {
		return nil, 0, err
	}
	return clients, total, nil
}

// Update persists a client's mutable fields (name / type / status) within its
// organization and reports whether a row matched.
func (d *AppClientDAO) Update(c *AppClient) error {
	res := d.db.Model(&AppClient{}).
		Where("id = ? AND organization_id = ?", c.ID, c.OrganizationID).
		Updates(map[string]interface{}{
			"name":        c.Name,
			"client_type": c.ClientType,
			"status":      c.Status,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errno.ClientNotExistErr
	}
	return nil
}

// Delete removes a client within its organization.
func (d *AppClientDAO) Delete(organizationID, clientID int64) error {
	res := d.db.Where("id = ? AND organization_id = ?", clientID, organizationID).
		Delete(&AppClient{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errno.ClientNotExistErr
	}
	return nil
}
