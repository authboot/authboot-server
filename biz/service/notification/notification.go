package notification

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/authboot/authboot-server/biz/dal/db"
	notification "github.com/authboot/authboot-server/biz/model/notification"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/errno"
)

// notifCache caches each user's latest notification id, used to short-circuit
// the polling check (CheckNewNotifications) without hitting the database.
var notifCache redis.Notification

type NotificationService struct {
	ctx context.Context
	c   *app.RequestContext

	notificationDAO *db.NotificationDAO
}

// NewNotificationService create notification service
func NewNotificationService(ctx context.Context, c *app.RequestContext) *NotificationService {
	return &NotificationService{
		ctx: ctx,
		c:   c,

		notificationDAO: db.INotificationDAO,
	}
}

// currentUserID reads the authenticated user id set by the JWT middleware.
func (s *NotificationService) currentUserID() (int64, error) {
	v, ok := s.c.Get("current_user_id")
	if !ok {
		return 0, errno.AuthorizationFailedErr
	}
	id, ok := v.(int64)
	if !ok {
		return 0, errno.AuthorizationFailedErr
	}
	return id, nil
}

// ListNotifications returns a page of the current user's notifications together
// with the total count and the unread count.
func (s *NotificationService) ListNotifications(req *notification.ListNotificationsRequest) ([]*notification.Notification, int64, int64, error) {
	userID, err := s.currentUserID()
	if err != nil {
		return nil, 0, 0, err
	}
	list, total, err := s.notificationDAO.ListNotifications(userID, int(req.Status), int(req.Type), int(req.Page), int(req.PageSize))
	if err != nil {
		return nil, 0, 0, err
	}
	unread, err := s.notificationDAO.CountUnread(userID)
	if err != nil {
		return nil, 0, 0, err
	}
	infos := make([]*notification.Notification, 0, len(list))
	for _, n := range list {
		infos = append(infos, toNotificationInfo(n))
	}
	return infos, total, unread, nil
}

// GetNotification returns one of the current user's notifications by id.
func (s *NotificationService) GetNotification(req *notification.GetNotificationRequest) (*notification.Notification, error) {
	userID, err := s.currentUserID()
	if err != nil {
		return nil, err
	}
	n, err := s.notificationDAO.QueryNotification(userID, req.Id)
	if err != nil {
		return nil, err
	}
	return toNotificationInfo(n), nil
}

// ReadNotification marks one notification as read and returns the updated record.
func (s *NotificationService) ReadNotification(req *notification.ReadNotificationRequest) (*notification.Notification, error) {
	userID, err := s.currentUserID()
	if err != nil {
		return nil, err
	}
	n, err := s.notificationDAO.MarkNotificationRead(userID, req.Id)
	if err != nil {
		return nil, err
	}
	return toNotificationInfo(n), nil
}

// ReadAllNotifications marks all of the current user's unread notifications as
// read and returns the number affected.
func (s *NotificationService) ReadAllNotifications(req *notification.ReadAllNotificationsRequest) (int64, error) {
	userID, err := s.currentUserID()
	if err != nil {
		return 0, err
	}
	return s.notificationDAO.MarkAllNotificationsRead(userID)
}

// DeleteNotification deletes one of the current user's notifications by id.
func (s *NotificationService) DeleteNotification(req *notification.DeleteNotificationRequest) error {
	userID, err := s.currentUserID()
	if err != nil {
		return err
	}
	if err := s.notificationDAO.DeleteNotification(userID, req.Id); err != nil {
		return err
	}
	// 删除的可能正是最新一条，使缓存失效，下次轮询回源重建。
	_ = notifCache.DelLatest(userID)
	return nil
}

// DeleteAllNotifications deletes all of the current user's notifications and
// returns the number affected.
func (s *NotificationService) DeleteAllNotifications(req *notification.DeleteAllNotificationsRequest) (int64, error) {
	userID, err := s.currentUserID()
	if err != nil {
		return 0, err
	}
	affected, err := s.notificationDAO.DeleteAllNotifications(userID)
	if err != nil {
		return 0, err
	}
	// 全部删除后最新 id 不复存在，清掉缓存。
	_ = notifCache.DelLatest(userID)
	return affected, nil
}

// CheckNewNotifications is the polling fast path: it reports whether the user
// has notifications newer than the id the client last saw, along with the
// current latest id and unread count.
//
// The latest id is served from Redis when warm, falling back to the database
// (and warming the cache) on a miss or cache error, so the common poll costs a
// single Redis GET instead of a DB query.
func (s *NotificationService) CheckNewNotifications(req *notification.CheckNewNotificationsRequest) (hasNew bool, latestID int64, unread int64, err error) {
	userID, err := s.currentUserID()
	if err != nil {
		return false, 0, 0, err
	}

	// 快路径：优先读缓存的最新通知 id；未命中或缓存出错则回源数据库并预热缓存。
	latestID, found, cerr := notifCache.GetLatest(userID)
	if cerr != nil || !found {
		latestID, err = s.notificationDAO.GetLatestNotificationID(userID)
		if err != nil {
			return false, 0, 0, err
		}
		if latestID > 0 {
			_ = notifCache.SetLatest(userID, latestID)
		}
	}

	unread, err = s.notificationDAO.CountUnread(userID)
	if err != nil {
		return false, 0, 0, err
	}

	// New notifications always carry a higher id than what the client saw.
	hasNew = latestID > req.LastNotificationId
	return hasNew, latestID, unread, nil
}

// toNotificationInfo maps a db row to the API model.
func toNotificationInfo(n *db.Notification) *notification.Notification {
	return &notification.Notification{
		Id:        n.ID,
		UserId:    n.UserID,
		Type:      notification.NotificationType(n.Type),
		Level:     notification.NotificationLevel(n.Level),
		Title:     n.Title,
		Content:   n.Content,
		Url:       n.URL,
		Status:    notification.NotificationStatus(n.Status),
		Data:      n.Data,
		CreatedAt: n.CreatedAt,
		ReadAt:    n.ReadAt,
	}
}
