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

	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const UserTableName = "tb_user"

type User struct {
	ID int64 `json:"id"`
	// Composite indexes serve the org dashboard's COUNT/SUM aggregates:
	// idx_users_org_created (org + created_at) for growth windows and
	// idx_users_org_status (org + status) for the disabled count.
	OrganizationID  int64  `json:"organization_id" gorm:"column:organization_id;index;index:idx_users_org_created,priority:1;index:idx_users_org_status,priority:1"`
	UserName        string `json:"user_name"`
	Password        string `json:"password"`
	Avatar          string `json:"avatar"`
	BackgroundImage string `json:"background_image"`
	Signature       string `json:"signature"`
	// Settings holds arbitrary user preferences as a JSON object (stored as a
	// JSON string so the struct stays comparable).
	Settings datatypes.JSON `json:"settings" gorm:"column:settings;type:json"`
	// Gender uses the common.Gender enum values (0 unknown / 1 male / 2 female / 3 other).
	Gender   int8   `json:"gender" gorm:"column:gender;type:tinyint;not null;default:0"`
	Birthday string `json:"birthday" gorm:"column:birthday;type:varchar(32)"`
	Bio      string `json:"bio" gorm:"column:bio;type:varchar(512)"`
	// Status uses the shared constants.StatusEnabled / StatusDisabled values.
	Status int8 `json:"status" gorm:"column:status;type:tinyint;not null;default:1;index;index:idx_users_org_status,priority:2"`
	CreatedAt int64 `json:"created_at" gorm:"column:created_at;autoCreateTime;index:idx_users_org_created,priority:2"`
	UpdatedAt int64 `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
}

// TableName defines the table name for the User struct.
func (User) TableName() string { return constants.UserTableName }

// UserDAO is the data-access handle for the user table. It wraps a *gorm.DB so
// the same methods can run either on the global connection (via the package
// default instance Users) or inside a transaction (via WithTx).
type UserDAO struct {
	db *gorm.DB
}

// NewUserDAO builds a UserDAO bound to the given connection.
func NewUserDAO(db *gorm.DB) *UserDAO {
	return &UserDAO{db: db}
}

// WithTx returns a UserDAO that runs its queries on the given transaction,
// letting callers compose multi-table writes in a single DB.Transaction.
func (d *UserDAO) WithTx(tx *gorm.DB) *UserDAO {
	return &UserDAO{db: tx}
}

// CreateUser create user info
func (d *UserDAO) CreateUser(user *User) (int64, error) {
	err := d.db.Create(user).Error
	if err != nil {
		return 0, err
	}
	return user.ID, err
}

// QueryUser query User by user_name (legacy global lookup, kept for compatibility).
func (d *UserDAO) QueryUser(userName string) (*User, error) {
	var user User
	if err := d.db.Where("user_name = ?", userName).Find(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// QueryUserInOrg query a User by user_name within a single organization (user pool boundary).
func (d *UserDAO) QueryUserInOrg(organizationID int64, userName string) (*User, error) {
	var user User
	if err := d.db.Where("organization_id = ? AND user_name = ?", organizationID, userName).
		Find(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// QueryUserById get user in the database by user id
func (d *UserDAO) QueryUserById(userID int64) (*User, error) {
	var user User

	if err := d.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errno.UserIsNotExistErr
		}
		return nil, err
	}

	return &user, nil
}

// QueryUserByIdInOrg gets a user by id but only if it belongs to the given organization.
// This enforces the organization isolation boundary: a token scoped to org B must not be
// able to read org A's user simply because the user_id exists.
func (d *UserDAO) QueryUserByIdInOrg(organizationID, userID int64) (*User, error) {
	var user User

	err := d.db.Where(
		"id = ? AND organization_id = ?",
		userID,
		organizationID,
	).First(&user).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errno.CrossOrganizationAccessErr
	}
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// VerifyUser verify username and password in the db
func (d *UserDAO) VerifyUser(userName, password string) (int64, error) {
	var user User
	if err := d.db.Where("user_name = ? AND password = ?", userName, password).Find(&user).Error; err != nil {
		return 0, err
	}
	if user.ID == 0 {
		err := errno.PasswordIsNotVerified
		return user.ID, err
	}
	return user.ID, nil
}

// CheckUserExistById find if user exists
func (d *UserDAO) CheckUserExistById(userID int64) (bool, error) {
	var count int64

	if err := d.db.Model(&User{}).
		Where("id = ?", userID).
		Count(&count).Error; err != nil {
		return false, err
	}

	return count > 0, nil
}

// ListUsersInOrg returns a page of users within an organization (ordered by id)
// together with the total count, enforcing the organization isolation boundary.
func (d *UserDAO) ListUsersInOrg(organizationID int64, offset, limit int) ([]*User, int64, error) {
	var users []*User
	var total int64
	if err := d.db.Model(&User{}).Where("organization_id = ?", organizationID).
		Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := d.db.Where("organization_id = ?", organizationID).
		Order("id asc").Offset(offset).Limit(limit).Find(&users).Error; err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

// UpdateUser updates a user's mutable profile fields within its organization.
func (d *UserDAO) UpdateUser(user *User) error {
	return d.db.Model(&User{}).
		Where("id = ? AND organization_id = ?", user.ID, user.OrganizationID).
		Updates(map[string]interface{}{
			"user_name": user.UserName,
			"avatar":    user.Avatar,
			"gender":    user.Gender,
			"birthday":  user.Birthday,
			"bio":       user.Bio,
		}).Error
}

// SetUserStatus sets a user's status within its organization (enabled/disabled).
func (d *UserDAO) SetUserStatus(organizationID, userID int64, status int) error {
	return d.db.Model(&User{}).
		Where("id = ? AND organization_id = ?", userID, organizationID).
		Update("status", status).Error
}

// UpdatePassword replaces a user's password hash within its organization.
func (d *UserDAO) UpdatePassword(organizationID, userID int64, passwordHash string) error {
	return d.db.Model(&User{}).
		Where("id = ? AND organization_id = ?", userID, organizationID).
		Update("password", passwordHash).Error
}
