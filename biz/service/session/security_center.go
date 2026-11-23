package session

import (
	"fmt"
	"strings"
	"time"

	"github.com/authboot/authboot-server/biz/dal/db"
	model "github.com/authboot/authboot-server/biz/model/security"
	sessionmodel "github.com/authboot/authboot-server/biz/model/session"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/authboot/authboot-server/pkg/utils"
	"gorm.io/gorm"
)

func (s *SessionService) securityOwner() (int64, int64, string, error) {
	user, org, sid := s.c.GetInt64(jwt.CtxKeyUserID), s.c.GetInt64(jwt.CtxKeyOrgID), s.c.GetString(jwt.CtxKeySessionID)
	if user <= 0 || org <= 0 || sid == "" {
		return 0, 0, "", errno.AuthorizationFailedErr
	}
	rec, err := sessionStore.Get(jwt.SubjectUser, sid)
	if err != nil || rec.AccountID != user || rec.OrganizationID != org {
		return 0, 0, "", errno.AuthorizationFailedErr
	}
	return org, user, sid, nil
}

// ClientSummary is deliberately coarse display metadata, never identity proof.
func ClientSummary(ua string) (browser, os string) {
	browser, os = "Unknown", "Unknown"
	for _, p := range [][2]string{{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Chrome/", "Chrome"}, {"Firefox/", "Firefox"}, {"Safari/", "Safari"}} {
		if strings.Contains(ua, p[0]) {
			browser = p[1]
			break
		}
	}
	for _, p := range [][2]string{{"Android", "Android"}, {"iPhone", "iOS"}, {"iPad", "iPadOS"}, {"Windows", "Windows"}, {"Macintosh", "macOS"}, {"Linux", "Linux"}} {
		if strings.Contains(ua, p[0]) {
			os = p[1]
			break
		}
	}
	return
}

func (s *SessionService) MyDevices(req *model.PageRequest) (*model.DevicesResponse, error) {
	org, user, sid, err := s.securityOwner()
	if err != nil {
		return nil, err
	}
	current, err := sessionStore.Get(jwt.SubjectUser, sid)
	if err != nil {
		return nil, err
	}
	page, size := normalizePaging(req.Page, req.PageSize)
	query := db.DB.Model(&db.UserDevice{}).Where("organization_id = ? AND user_id = ?", org, user)
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}
	var devices []db.UserDevice
	if err := query.Order("last_used_at DESC, id DESC").Offset((page - 1) * size).Limit(size).Find(&devices).Error; err != nil {
		return nil, err
	}
	sessions, err := sessionStore.ListForUser(jwt.SubjectUser, user)
	if err != nil {
		return nil, err
	}
	out := &model.DevicesResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg, Total: total, Devices: []*model.Device{}}
	for _, d := range devices {
		browser, os := ClientSummary(d.UserAgent)
		v := &model.Device{DeviceId: d.DeviceID, DeviceName: d.DeviceName, Current: d.DeviceID != "" && d.DeviceID == current.DeviceID, LastLoginAt: d.LastUsedAt, LastActiveAt: d.LastActiveAt, Ip: d.LastIP, Location: LocationProto(d.LastLocation), LastActiveIp: d.LastActiveIP, LastActiveLocation: LocationProto(d.LastActiveLocation), Status: "inactive", Browser: browser, Os: os}
		for _, r := range sessions {
			if r.OrganizationID == org && r.AccountID == user && r.DeviceID == d.DeviceID {
				v.ActiveSessions++
				if r.LastActiveAt > v.LastActiveAt {
					v.LastActiveAt, v.LastActiveIp, v.LastActiveLocation = r.LastActiveAt, r.LastActiveIP, LocationProto(r.LastActiveLocation)
				}
			}
		}
		if v.ActiveSessions > 0 {
			v.Status = "active"
		}
		out.Devices = append(out.Devices, v)
	}
	return out, nil
}

func (s *SessionService) MySessions(req *model.PageRequest) (*sessionmodel.ListSessionsResponse, error) {
	org, user, sid, err := s.securityOwner()
	if err != nil {
		return nil, err
	}
	all, err := sessionStore.ListForUser(jwt.SubjectUser, user)
	if err != nil {
		return nil, err
	}
	scoped := make([]*redis.SessionRecord, 0, len(all))
	for _, r := range all {
		if r.OrganizationID == org && r.AccountID == user {
			scoped = append(scoped, r)
		}
	}
	page, size := normalizePaging(req.Page, req.PageSize)
	items, total := paginateSessions(scoped, page, size)
	for _, v := range items {
		v.Current = v.SessionId == sid
	}
	return &sessionmodel.ListSessionsResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg, Sessions: items, Total: total}, nil
}

func (s *SessionService) MyEvents(req *model.PageRequest) (*model.EventsResponse, error) {
	org, user, _, err := s.securityOwner()
	if err != nil {
		return nil, err
	}
	page, size := normalizePaging(req.Page, req.PageSize)
	q := db.DB.Model(&db.UserSecurityEvent{}).Where("organization_id = ? AND user_id = ?", org, user)
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, err
	}
	var rows []db.UserSecurityEvent
	if err := q.Order("created_at DESC, id DESC").Offset((page - 1) * size).Limit(size).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := &model.EventsResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg, Total: total, Events: []*model.Event{}}
	for _, e := range rows {
		out.Events = append(out.Events, &model.Event{Id: e.ID, SessionId: e.SessionID, DeviceId: e.DeviceID, Kind: e.Kind, Ip: e.IP, Location: LocationProto(e.Location), Status: e.Status, CreatedAt: e.CreatedAt, ResolvedAt: e.ResolvedAt, NotifyStatus: e.NotifyStatus})
	}
	return out, nil
}

func (s *SessionService) RevokeMySessions(req *model.RevokeRequest) (*model.ActionResponse, error) {
	org, user, sid, err := s.securityOwner()
	if err != nil {
		return nil, err
	}
	if req.Mode != "others" && req.Mode != "device" || req.Mode == "device" && req.DeviceId == "" {
		return nil, errno.ParamErr
	}
	ids, err := sessionStore.RevokeUserSelection(org, user, sid, req.Mode, req.DeviceId)
	if err != nil {
		return nil, err
	}
	s.mirrorRevoked(org, user, ids)
	return &model.ActionResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg, RevokedSessions: int64(len(ids))}, nil
}

func (s *SessionService) mirrorRevoked(org, user int64, ids []string) {
	if len(ids) == 0 {
		return
	}
	if err := db.DB.Model(&db.UserSessionRow{}).Where("organization_id = ? AND user_id = ? AND session_id IN ?", org, user, ids).Update("status", db.SessionRowRevoked).Error; err != nil {
		// Audit mirror failure never undoes authoritative Redis revocation.
		securityLog(s.ctx, "persist revoked sessions", err)
	}
}

func (s *SessionService) ConfirmSecurityEvent(req *model.ConfirmRequest) (*model.ActionResponse, error) {
	org, user, sid, err := s.securityOwner()
	if err != nil {
		return nil, err
	}
	if req.EventId == "" || (req.Decision != "me" && req.Decision != "not_me") {
		return nil, errno.ParamErr
	}
	var event db.UserSecurityEvent
	if err := db.DB.Where("id = ? AND organization_id = ? AND user_id = ?", req.EventId, org, user).First(&event).Error; err != nil {
		return nil, errno.AuthorizationFailedErr
	}
	if req.Decision == "me" && event.SessionID == sid {
		return nil, errno.PermissionDeniedErr
	}
	// Throttle password attempts, including valid proofs, per owner across sessions.
	if !(redis.Code{}).Allow(fmt.Sprintf("security-proof:%d:%d", org, user), 5, 5*time.Minute) {
		return nil, errno.AuthorizationFailedErr
	}
	u, err := s.userDAO.QueryUserByIdInOrg(org, user)
	if err != nil {
		return nil, err
	}
	verified := req.Password != "" && u.Password != "" && utils.VerifyPassword(req.Password, u.Password)
	independentOTP := false
	if !verified && req.Password == "" && req.Credential != "" && (req.IdentityType == "email" || req.IdentityType == "phone") {
		identity, err := db.NewUserIdentityDAO(db.DB).QueryIdentity(org, req.IdentityType, req.IdentityValue)
		// A contact added after the event is not an independent recovery factor.
		verified = err == nil && identity.UserID == user &&
			(req.Decision != "me" || identity.CreatedAt > 0 && identity.CreatedAt < event.CreatedAt) &&
			(redis.Code{}).Verify("login", req.IdentityValue, req.Credential)
		independentOTP = verified
	}
	if !verified {
		return nil, errno.AuthorizationFailedErr
	}
	out := &model.ActionResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}
	// A DB row lock serializes conflicting decisions. On Redis failure the
	// transaction rolls back; retrying a successful revoke is safe.
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		var locked db.UserSecurityEvent
		if err := tx.Clauses(securityRowLock()).Where("id = ? AND organization_id = ? AND user_id = ?", event.ID, org, user).First(&locked).Error; err != nil {
			return err
		}
		current, err := sessionStore.GetWithDB(tx, jwt.SubjectUser, sid)
		if err != nil || current.AccountID != user || current.OrganizationID != org {
			return errno.AuthorizationFailedErr
		}
		if req.Decision == "me" {
			if locked.Status == "not_me" || locked.SessionID == sid {
				return errno.PermissionDeniedErr
			}
			if !independentOTP {
				// Equal-second timestamps and missing legacy timestamps fail closed.
				if current.CreatedAt <= 0 || current.CreatedAt >= locked.CreatedAt {
					return errno.PermissionDeniedErr
				}
				var unresolved int64
				if err := tx.Model(&db.UserSecurityEvent{}).Where(
					"organization_id = ? AND user_id = ? AND session_id = ? AND status <> ?",
					org, user, sid, "me").Count(&unresolved).Error; err != nil {
					return err
				}
				if unresolved != 0 {
					return errno.PermissionDeniedErr
				}
			}
		}
		if locked.Status == req.Decision {
			out.ChangePasswordRequired = req.Decision == "not_me"
			if out.ChangePasswordRequired {
				out.Message = "可疑会话已撤销，请立即修改或重置密码，并检查绑定的联系方式"
			}
			return nil
		}
		if locked.Status != "pending" && !(locked.Status == "me" && req.Decision == "not_me") {
			return errno.ParamErr
		}
		if req.Decision == "not_me" {
			ids, err := sessionStore.RevokeUserSelection(org, user, sid, "session", locked.SessionID)
			if err != nil {
				return err
			}
			out.RevokedSessions = int64(len(ids))
			out.ChangePasswordRequired = true
			out.Message = "可疑会话已撤销，请立即修改或重置密码，并检查绑定的联系方式"
		}
		return tx.Model(&locked).Updates(map[string]interface{}{"status": req.Decision, "resolved_at": time.Now().Unix()}).Error
	})
	if err != nil {
		return nil, err
	}
	if req.Decision == "not_me" {
		s.mirrorRevoked(org, user, []string{event.SessionID})
	}
	return out, nil
}
