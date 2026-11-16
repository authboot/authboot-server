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

	"github.com/authboot/authboot-server/pkg/errno"
)

const notificationTableName = "tb_notification"

// notification status values (mirror notification.NotificationStatus).
const (
	notificationStatusUnread = 1
	notificationStatusRead   = 2
)

// Notification is a single in-app notification delivered to a user.
type Notification struct {
	ID        int64  `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID    int64  `json:"user_id" gorm:"column:user_id;not null;index:idx_user_status"`
	Type      int8   `json:"type" gorm:"column:type;not null;default:0"`
	Level     int8   `json:"level" gorm:"column:level;not null;default:0"`
	Title     string `json:"title" gorm:"type:varchar(255);not null"`
	Content   string `json:"content" gorm:"type:text"`
	URL       string `json:"url" gorm:"column:url;type:varchar(512)"`
	Status    int8   `json:"status" gorm:"column:status;not null;default:1;index:idx_user_status"`
	Data      string `json:"data" gorm:"type:text"`
	CreatedAt int64  `json:"created_at" gorm:"column:created_at;not null;index"`
	ReadAt    int64  `json:"read_at" gorm:"column:read_at;not null;default:0"`
}

// TableName set table name to make gorm can correctly identify
func (Notification) TableName() string {
	return notificationTableName
}

// NotificationDAO is the data-access handle for the notification table. It wraps
// a *gorm.DB so the same methods run on the global connection (via the package
// default instance Notifications) or inside a transaction (via WithTx).
type NotificationDAO struct {
	db *gorm.DB
}

// NewNotificationDAO builds a NotificationDAO bound to the given connection.
func NewNotificationDAO(db *gorm.DB) *NotificationDAO {
	return &NotificationDAO{db: db}
}

// WithTx returns a NotificationDAO that runs its queries on the given transaction.
func (d *NotificationDAO) WithTx(tx *gorm.DB) *NotificationDAO {
	return &NotificationDAO{db: tx}
}

// CreateNotification inserts a new notification and returns its id. It defaults
// CreatedAt to now and Status to unread when unset.
func (d *NotificationDAO) CreateNotification(n *Notification) (int64, error) {
	if n.CreatedAt == 0 {
		n.CreatedAt = time.Now().Unix()
	}
	if n.Status == 0 {
		n.Status = notificationStatusUnread
	}
	if err := d.db.Create(n).Error; err != nil {
		return 0, err
	}
	return n.ID, nil
}

// ListNotifications returns a page of a user's notifications filtered by
// optional status/type (0 = no filter), newest first, plus the total count.
func (d *NotificationDAO) ListNotifications(userID int64, status, ntype, page, pageSize int) ([]*Notification, int64, error) {
	base := func() *gorm.DB {
		q := d.db.Model(&Notification{}).Where("user_id = ?", userID)
		if status > 0 {
			q = q.Where("status = ?", status)
		}
		if ntype > 0 {
			q = q.Where("type = ?", ntype)
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

	var list []*Notification
	if err := base().Order("id desc").
		Offset((page - 1) * pageSize).Limit(pageSize).
		Find(&list).Error; err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// CountUnread returns the number of unread notifications for a user.
func (d *NotificationDAO) CountUnread(userID int64) (int64, error) {
	var n int64
	err := d.db.Model(&Notification{}).
		Where("user_id = ? AND status = ?", userID, notificationStatusUnread).
		Count(&n).Error
	return n, err
}

// GetLatestNotificationID returns the newest notification id for a user, or 0
// when the user has no notifications.
func (d *NotificationDAO) GetLatestNotificationID(userID int64) (int64, error) {
	var n Notification
	if err := d.db.Select("id").Where("user_id = ?", userID).
		Order("id desc").Limit(1).Find(&n).Error; err != nil {
		return 0, err
	}
	return n.ID, nil
}

// QueryNotification returns a user's notification by id (scoped to the user),
// or NotificationNotExistErr when it does not exist.
func (d *NotificationDAO) QueryNotification(userID, id int64) (*Notification, error) {
	var n Notification
	if err := d.db.Where("id = ? AND user_id = ?", id, userID).Find(&n).Error; err != nil {
		return nil, err
	}
	if n.ID == 0 {
		return nil, errno.NotificationNotExistErr
	}
	return &n, nil
}

// MarkNotificationRead marks a user's notification as read and returns the
// updated record. Reading an already-read notification is a no-op.
func (d *NotificationDAO) MarkNotificationRead(userID, id int64) (*Notification, error) {
	n, err := d.QueryNotification(userID, id)
	if err != nil {
		return nil, err
	}
	if n.Status != notificationStatusRead {
		readAt := time.Now().Unix()
		if err := d.db.Model(&Notification{}).
			Where("id = ? AND user_id = ?", id, userID).
			Updates(map[string]interface{}{"status": notificationStatusRead, "read_at": readAt}).Error; err != nil {
			return nil, err
		}
		n.Status = notificationStatusRead
		n.ReadAt = readAt
	}
	return n, nil
}

// MarkAllNotificationsRead marks all unread notifications of a user as read and
// returns the number of affected rows.
func (d *NotificationDAO) MarkAllNotificationsRead(userID int64) (int64, error) {
	result := d.db.Model(&Notification{}).
		Where("user_id = ? AND status = ?", userID, notificationStatusUnread).
		Updates(map[string]interface{}{"status": notificationStatusRead, "read_at": time.Now().Unix()})
	return result.RowsAffected, result.Error
}

// DeleteNotification deletes a user's notification by id, returning
// NotificationNotExistErr when nothing was deleted.
func (d *NotificationDAO) DeleteNotification(userID, id int64) error {
	result := d.db.Where("id = ? AND user_id = ?", id, userID).Delete(&Notification{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errno.NotificationNotExistErr
	}
	return nil
}

// DeleteAllNotifications deletes all notifications of a user and returns the
// number of affected rows.
func (d *NotificationDAO) DeleteAllNotifications(userID int64) (int64, error) {
	result := d.db.Where("user_id = ?", userID).Delete(&Notification{})
	return result.RowsAffected, result.Error
}
