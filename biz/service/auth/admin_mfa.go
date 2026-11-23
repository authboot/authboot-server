package auth

import (
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/authboot/authboot-server/biz/dal/db"
	model "github.com/authboot/authboot-server/biz/model/auth"
	"github.com/authboot/authboot-server/biz/mw/audit"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/authboot/authboot-server/pkg/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type MFARequest struct {
	Password       string `json:"password"`
	Code           string `json:"code"`
	Recovery       bool   `json:"recovery"`
	ChallengeToken string `json:"challenge_token"`
	Scope          string `json:"scope"`
}

func mfaCipher() (*utils.MFASecretCipher, error) {
	return utils.NewMFASecretCipher(os.Getenv("ADMIN_MFA_ENCRYPTION_KEY"))
}

func (s *AdminAuthService) newMFAChallenge(user *db.AdminUser, req *model.AdminLoginRequest) (*model.AdminLoginResponse, error) {
	// An enabled account never falls back to password-only when the key is absent.
	if _, err := mfaCipher(); err != nil {
		return nil, err
	}
	if !(redis.Code{}).Allow(fmt.Sprintf("mfa-challenge:admin:%d", user.ID), 5, 5*time.Minute) {
		return nil, errno.AuthorizationFailedErr
	}
	now := time.Now()
	token, err := db.NewAdminMFAChallenge(db.DB, db.AdminMFAChallenge{
		AccountID: user.ID, Generation: user.MFAGeneration, DeviceID: req.DeviceId, DeviceName: req.DeviceName,
		IP: s.c.ClientIP(), UserAgent: string(s.c.UserAgent()), PasswordHash: user.Password,
	}, now)
	if err != nil {
		return nil, err
	}
	return &model.AdminLoginResponse{Code: errno.SuccessCode, Message: "MFA verification required", MfaRequired: true, MfaChallengeToken: token, MfaChallengeExpiresAt: now.Add(3 * time.Minute).Unix()}, nil
}

func (s *AdminAuthService) VerifyAdminMFA(req *MFARequest) (*model.AdminLoginResponse, error) {
	now := time.Now()
	challenge, err := db.AttemptAdminMFAChallenge(db.DB, req.ChallengeToken, s.c.ClientIP(), string(s.c.UserAgent()), now)
	if err != nil {
		return nil, errno.AuthorizationFailedErr
	}
	if !(redis.Code{}).Allow(fmt.Sprintf("mfa-proof:admin:%d", challenge.AccountID), 5, 5*time.Minute) {
		return nil, errno.AuthorizationFailedErr
	}
	cipher, err := mfaCipher()
	if err != nil {
		return nil, err
	}
	// MFA state, challenge and recovery use commit together.
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		var user db.AdminUser
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, challenge.AccountID).Error; err != nil {
			return err
		}
		if user.Status != 1 || !user.MFAEnabled || user.MFAGeneration != challenge.Generation || user.Password != challenge.PasswordHash {
			return errno.AuthorizationFailedErr
		}
		if err := db.ConsumeAdminMFA(tx, cipher, user.ID, req.Code, req.Recovery, now.Unix()); err != nil {
			return err
		}
		return db.ConsumeAdminMFAChallenge(tx, challenge, now)
	})
	if err != nil {
		return nil, errno.AuthorizationFailedErr
	}
	if err := db.ActiveSubject(jwt.SubjectAdmin, challenge.AccountID, 0); err != nil {
		return nil, err
	}
	rec, err := sessionStore.Create(jwt.SubjectAdmin, challenge.AccountID, 0, challenge.DeviceID, challenge.DeviceName, redis.DefaultSessionTTL, redis.LoginMetadata{MFAGeneration: challenge.Generation, IP: challenge.IP, UserAgent: challenge.UserAgent})
	if err != nil {
		return nil, err
	}
	access, expiry, err := jwt.GenerateAdminAccessToken(rec.AccountID, 0, rec.SessionID, s.adminAccessTTL(0))
	if err != nil {
		return nil, err
	}
	audit.Record(s.c, &audit.Entry{Action: "admin.login.mfa", AdminID: rec.AccountID, SessionID: rec.SessionID, Success: true})
	_ = db.InsertAdminLoginLog(&db.AdminLoginLog{AdminID: rec.AccountID, DeviceID: rec.DeviceID, DeviceName: rec.DeviceName, IP: challenge.IP, UserAgent: challenge.UserAgent, Success: true})
	_ = db.UpsertAdminDevice(rec.AccountID, rec.DeviceID, rec.DeviceName, challenge.IP, challenge.UserAgent, now.Unix())
	return &model.AdminLoginResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg, AccessToken: access, RefreshToken: rec.RefreshToken, AccessTokenExpiresAt: expiry, RefreshTokenExpiresAt: rec.ExpiresAt}, nil
}

func (s *AdminAuthService) AdminStepUp(req *MFARequest) (map[string]any, error) {
	id, err := s.currentAccountID()
	if err != nil {
		return nil, err
	}
	sid := s.currentSessionID()
	if sid == "" || !jwt.ValidAdminStepUpScope(req.Scope) {
		return nil, errno.ParamErr
	}
	if !(redis.Code{}).Allow(fmt.Sprintf("stepup:admin:%d", id), 5, 5*time.Minute) {
		return nil, errno.AuthorizationFailedErr
	}
	var token string
	now := time.Now()
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		var user db.AdminUser
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, id).Error; err != nil {
			return err
		}
		rec, err := sessionStore.GetWithDB(tx, jwt.SubjectAdmin, sid)
		if err != nil || rec.AccountID != id || rec.MFAGeneration != user.MFAGeneration || user.Status != 1 {
			return errno.AuthorizationFailedErr
		}
		if !utils.VerifyPassword(req.Password, user.Password) {
			return errno.AuthorizationFailedErr
		}
		if user.MFAEnabled {
			cipher, err := mfaCipher()
			if err != nil {
				return err
			}
			if err := db.ConsumeAdminMFA(tx, cipher, id, req.Code, req.Recovery, now.Unix()); err != nil {
				return err
			}
		}
		token, err = db.NewSecurityGrant(tx, db.SecurityGrant{Subject: jwt.SubjectAdmin, AccountID: id, OrganizationID: s.c.GetInt64(jwt.CtxKeyOrgID), SessionID: sid, Scope: req.Scope}, now, 2*time.Minute)
		return err
	})
	if err != nil {
		return nil, errno.AuthorizationFailedErr
	}
	return map[string]any{"code": errno.SuccessCode, "step_up_token": token, "expires_at": now.Add(2 * time.Minute).Unix()}, nil
}

// AdminMFAAction consumes its step-up proof in the same transaction as the
// change. No secret is exposed by status/account/read endpoints.
func (s *AdminAuthService) AdminMFAAction(action string, req *MFARequest) (map[string]any, error) {
	id, err := s.currentAccountID()
	if err != nil {
		return nil, err
	}
	if !(redis.Code{}).Allow(fmt.Sprintf("mfa-manage:admin:%d", id), 5, 5*time.Minute) {
		return nil, errno.AuthorizationFailedErr
	}
	cipher, err := mfaCipher()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := map[string]any{"code": errno.SuccessCode, "message": errno.SuccessMsg}
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		var user db.AdminUser
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, id).Error; err != nil {
			return err
		}
		rec, err := sessionStore.GetWithDB(tx, jwt.SubjectAdmin, s.currentSessionID())
		if err != nil || rec.AccountID != id || rec.MFAGeneration != user.MFAGeneration || user.Status != 1 {
			return errno.AuthorizationFailedErr
		}
		if err := db.ConsumeSecurityGrant(tx, string(s.c.GetHeader("X-Step-Up-Token")), db.SecurityGrant{Subject: jwt.SubjectAdmin, AccountID: id, OrganizationID: s.c.GetInt64(jwt.CtxKeyOrgID), SessionID: rec.SessionID, Scope: "mfa:" + action}, now); err != nil {
			return err
		}
		var state db.AdminMFA
		stateErr := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("account_id = ?", id).First(&state).Error
		if stateErr != nil && stateErr != gorm.ErrRecordNotFound {
			return stateErr
		}
		switch action {
		case "setup":
			if user.MFAEnabled {
				return errno.ParamErr
			}
			secret, err := utils.NewTOTPSecret()
			if err != nil {
				return err
			}
			encrypted, err := cipher.Seal(secret, db.MFABinding(id))
			if err != nil {
				return err
			}
			state = db.AdminMFA{AccountID: id, Secret: encrypted, LastCounter: -1, SetupExpiresAt: now.Add(10 * time.Minute).Unix(), Generation: user.MFAGeneration}
			if err := tx.Save(&state).Error; err != nil {
				return err
			}
			out["secret"] = secret
			out["otpauth_uri"] = "otpauth://totp/" + url.PathEscape("Authboot:"+user.Email) + "?secret=" + secret + "&issuer=Authboot&algorithm=SHA1&digits=6&period=30"
			out["expires_at"] = state.SetupExpiresAt
		case "confirm":
			if stateErr != nil || user.MFAEnabled || state.SetupExpiresAt <= now.Unix() {
				return errno.AuthorizationFailedErr
			}
			secret, err := cipher.Open(state.Secret, db.MFABinding(id))
			if err != nil {
				return err
			}
			counter, err := utils.MatchTOTP(secret, req.Code, now.Unix(), state.LastCounter)
			if err != nil {
				return err
			}
			state.Enabled = true
			state.LastCounter = counter
			state.Generation = user.MFAGeneration + 1
			state.SetupExpiresAt = 0
			if err := tx.Save(&state).Error; err != nil {
				return err
			}
			if err := tx.Model(&user).Updates(map[string]any{"mfa_enabled": true, "mfa_generation": state.Generation}).Error; err != nil {
				return err
			}
			if err := tx.Create(&db.RevocationOutbox{Subject: "admin", AccountID: id, BeforeVersion: state.Generation, NextAttemptAt: now.Unix()}).Error; err != nil {
				return err
			}
			codes, err := db.ReplaceAdminMFARecovery(tx, id)
			if err != nil {
				return err
			}
			out["recovery_codes"] = codes
			out["reauthentication_required"] = true
		case "disable":
			if !user.MFAEnabled {
				return errno.ParamErr
			}
			nextGeneration := user.MFAGeneration + 1
			if err := tx.Where("account_id = ?", id).Delete(&db.AdminMFA{}).Error; err != nil {
				return err
			}
			if err := tx.Where("account_id = ?", id).Delete(&db.AdminMFARecovery{}).Error; err != nil {
				return err
			}
			if err := tx.Model(&user).Updates(map[string]any{"mfa_enabled": false, "mfa_generation": nextGeneration}).Error; err != nil {
				return err
			}
			if err := tx.Create(&db.RevocationOutbox{Subject: "admin", AccountID: id, BeforeVersion: nextGeneration, NextAttemptAt: now.Unix()}).Error; err != nil {
				return err
			}
			out["reauthentication_required"] = true
		case "recovery":
			if !user.MFAEnabled {
				return errno.ParamErr
			}
			codes, err := db.ReplaceAdminMFARecovery(tx, id)
			if err != nil {
				return err
			}
			out["recovery_codes"] = codes
		default:
			return errno.ParamErr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	audit.Record(s.c, &audit.Entry{Action: "admin.mfa." + action, AdminID: id, SessionID: s.currentSessionID(), Success: true})
	return out, nil
}
