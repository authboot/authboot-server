package invitation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/model/invitation"
	"github.com/authboot/authboot-server/biz/model/membership"
	"github.com/authboot/authboot-server/biz/model/notification"
	"github.com/authboot/authboot-server/biz/mw/email"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
)

// notifCache warms the polling cache when an in-app notification is created.
var notifCache redis.Notification

type InviteService struct {
	ctx context.Context
	c   *app.RequestContext

	organizationDAO           *db.OrganizationDAO
	organizationMembershipDAO *db.OrganizationMembershipDAO
	organizationInvitationDAO *db.OrganizationInvitationDAO
	notificationDAO           *db.NotificationDAO
}

// NewInviteService create invitation service
func NewInviteService(ctx context.Context, c *app.RequestContext) *InviteService {
	return &InviteService{
		ctx: ctx,
		c:   c,

		organizationDAO:           db.IOrganizationDAO,
		organizationMembershipDAO: db.IOrganizationMembershipDAO,
		organizationInvitationDAO: db.IOrganizationInvitationDAO,
		notificationDAO:           db.INotificationDAO,
	}
}

// currentAccountID reads the authenticated account id set by the JWT middleware.
func (s *InviteService) currentAccountID() (int64, error) {
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

// InviteAdmin creates a pending invitation binding an email to an org role and
// returns the created invitation.
func (s *InviteService) InviteAdmin(req *invitation.InviteAdminRequest) (*invitation.OrganizationInvitation, error) {
	inviterID, err := s.currentAccountID()
	if err != nil {
		return nil, err
	}
	if _, err := s.organizationDAO.QueryOrganizationByID(req.OrganizationId); err != nil {
		return nil, err
	}

	token, err := newInvitationToken()
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	inv := &db.OrganizationInvitation{
		OrganizationID:   req.OrganizationId,
		Email:            req.Email,
		InviterAccountID: inviterID,
		Token:            token,
		Status:           db.InvitationStatusPending,
		ExpiredAt:        now + constants.InvitationTTL,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if _, err := s.organizationInvitationDAO.CreateInvitation(inv); err != nil {
		return nil, err
	}

	// 通知被邀请人：始终发邮件；若对方已注册，额外发一条站内通知。
	// 均为尽力而为，失败只记录日志，不影响邀请创建结果。
	s.notifyInvitee(inv)

	return toInvitationInfo(inv), nil
}

// notifyInvitee sends the invitation email and, when the invitee already has an
// account, an in-app notification. Both are best-effort.
func (s *InviteService) notifyInvitee(inv *db.OrganizationInvitation) {
	if body, err := buildInviteEmailHTML(inv); err != nil {
		hlog.CtxErrorf(s.ctx, "render invite email for %s failed: %v", inv.Email, err)
	} else if err := email.SendFor(s.ctx, inv.OrganizationID, &email.Message{
		To:      []string{inv.Email},
		Subject: "You have been invited to join an organization",
		HTML:    body,
	}); err != nil {
		hlog.CtxErrorf(s.ctx, "invite email to %s failed: %v", inv.Email, err)
	}

	// 判断被邀请人是否已注册（沿用登录使用的账号查询）。
	user, err := db.QueryAdminUser(inv.Email)
	if err != nil {
		// 未注册或查询失败：仅邮件通知即可。
		return
	}

	n := &db.Notification{
		UserID:  user.ID,
		Type:    int8(notification.NotificationType_NOTIFICATION_TYPE_ACCOUNT),
		Level:   int8(notification.NotificationLevel_NOTIFICATION_LEVEL_INFO),
		Title:   "组织邀请",
		Content: "你收到一个加入组织的邀请，请前往查看并接受。",
	}
	if _, err := s.notificationDAO.CreateNotification(n); err != nil {
		hlog.CtxErrorf(s.ctx, "create invite notification for account %d failed: %v", user.ID, err)
		return
	}
	// 预热轮询缓存，使对方轮询时立即感知到新通知。
	_ = notifCache.SetLatest(user.ID, n.ID)
}

// buildInviteEmailHTML renders the invitation email body from the template in
// biz/mw/email/templates, carrying the token and expiry.
func buildInviteEmailHTML(inv *db.OrganizationInvitation) (string, error) {
	return email.Render("invitation.html", map[string]any{
		"Token":    inv.Token,
		"ExpireAt": time.Unix(inv.ExpiredAt, 0).Format("2006-01-02 15:04:05"),
	})
}

// GetInvitation returns an invitation by id.
func (s *InviteService) GetInvitation(req *invitation.GetInvitationRequest) (*invitation.OrganizationInvitation, error) {
	inv, err := s.organizationInvitationDAO.QueryInvitationByID(req.InvitationId)
	if err != nil {
		return nil, err
	}
	return toInvitationInfo(inv), nil
}

// ListInvitations returns a page of an organization's invitations plus the total.
func (s *InviteService) ListInvitations(req *invitation.ListInvitationsRequest) ([]*invitation.OrganizationInvitation, int64, error) {
	list, total, err := s.organizationInvitationDAO.ListInvitationsByOrg(req.OrganizationId, int(req.Page), int(req.PageSize))
	if err != nil {
		return nil, 0, err
	}
	infos := make([]*invitation.OrganizationInvitation, 0, len(list))
	for _, inv := range list {
		infos = append(infos, toInvitationInfo(inv))
	}
	return infos, total, nil
}

// AcceptInvitation redeems a pending invitation for the current account,
// creating the corresponding organization membership.
func (s *InviteService) AcceptInvitation(req *invitation.AcceptInvitationRequest) (*membership.OrganizationMembership, error) {
	accountID, err := s.currentAccountID()
	if err != nil {
		return nil, err
	}

	inv, err := s.organizationInvitationDAO.QueryInvitationByToken(req.Token)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	// 只有待接受且未过期的邀请可被接受
	if inv.Status != db.InvitationStatusPending || inv.ExpiredAt <= now {
		return nil, errno.InvitationInvalidErr
	}

	m := &db.OrganizationMembership{
		OrganizationID: inv.OrganizationID,
		AccountID:      accountID,
		Status:         int8(membership.MembershipStatus_MEMBERSHIP_STATUS_ACTIVE),
	}
	if _, err := s.organizationMembershipDAO.CreateMembership(m); err != nil {
		return nil, err
	}
	if err := s.organizationInvitationDAO.AcceptInvitationRecord(inv.ID, accountID, now); err != nil {
		return nil, err
	}
	return toMembershipInfo(m), nil
}

// RevokeInvitation marks a pending invitation as revoked.
func (s *InviteService) RevokeInvitation(req *invitation.RevokeInvitationRequest) error {
	inv, err := s.organizationInvitationDAO.QueryInvitationByID(req.InvitationId)
	if err != nil {
		return err
	}
	if inv.Status != db.InvitationStatusPending {
		return errno.InvitationInvalidErr
	}
	return s.organizationInvitationDAO.UpdateInvitationStatus(inv.ID, db.InvitationStatusRevoked, time.Now().Unix())
}

// newInvitationToken returns a random 32-byte hex token.
func newInvitationToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// toInvitationInfo maps a db row to the API model (token stays server-side).
func toInvitationInfo(inv *db.OrganizationInvitation) *invitation.OrganizationInvitation {
	return &invitation.OrganizationInvitation{
		Id:                inv.ID,
		OrganizationId:    inv.OrganizationID,
		Email:             inv.Email,
		InviterAccountId:  inv.InviterAccountID,
		Status:            invitation.InvitationStatus(inv.Status),
		ExpiredAt:         inv.ExpiredAt,
		AcceptedAccountId: inv.AcceptedAccountID,
		CreatedAt:         inv.CreatedAt,
		UpdatedAt:         inv.UpdatedAt,
	}
}

// toMembershipInfo maps a db membership row to the API model.
func toMembershipInfo(m *db.OrganizationMembership) *membership.OrganizationMembership {
	return &membership.OrganizationMembership{
		Id:             m.ID,
		OrganizationId: m.OrganizationID,
		AccountId:      m.AccountID,
		Status:         membership.MembershipStatus(m.Status),
		CreatedAt:      m.CreatedAt.Unix(),
		UpdatedAt:      m.UpdatedAt.Unix(),
	}
}
