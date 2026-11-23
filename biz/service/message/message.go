package message

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/mail"
	"strings"
	"time"

	"github.com/authboot/authboot-server/biz/model/message"
	"github.com/authboot/authboot-server/biz/mw/captcha"
	"github.com/authboot/authboot-server/biz/mw/email"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/biz/mw/sms"
	"github.com/authboot/authboot-server/pkg/clientip"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/cloudwego/hertz/pkg/app"
)

// codeStore is the redis-backed one-time verification-code store. The scene
// strings written here must match those the auth service verifies against
// (e.g. the LOGIN scene maps to "login", which auth login checks).
var codeStore redis.Code

const (
	// codeTTL is how long an issued verification code stays valid.
	codeTTL = 5 * time.Minute
	// codeRetryAfterSeconds is the suggested client cool-down before a resend.
	codeRetryAfterSeconds = 60
)

type MessageService struct {
	ctx       context.Context
	c         *app.RequestContext
	sendEmail func(context.Context, *email.Message) error
}

// NewMessageService create message service
func NewMessageService(ctx context.Context, c *app.RequestContext) *MessageService {
	return &MessageService{ctx: ctx, c: c, sendEmail: email.Send}
}

// CreateCaptcha generates a new image captcha. It returns the captcha id, the
// base64-encoded PNG image, and the remaining validity in seconds. The client
// submits the id together with the user's answer to VerifyCaptcha.
func (s *MessageService) CreateCaptcha(req *message.CreateCaptchaRequest) (*message.CreateCaptchaResponse, error) {
	if sceneKey(message.MessageScene(req.Scene)) == "" {
		return nil, errno.ParamErr
	}
	if !codeStore.Allow("captcha:"+clientip.FromContext(s.c), 30, time.Minute) {
		return nil, errno.AuthorizationFailedErr
	}
	id, b64s, err := captcha.Generate()
	if err != nil {
		return nil, err
	}
	if err := codeStore.Store("captcha_binding", id, s.captchaBinding(int32(req.Scene)), time.Duration(captcha.ExpireSeconds())*time.Second); err != nil {
		return nil, err
	}

	return &message.CreateCaptchaResponse{
		Code:          errno.SuccessCode,
		Message:       errno.SuccessMsg,
		CaptchaId:     id,
		ImageBase64:   b64s,
		ExpireSeconds: int32(captcha.ExpireSeconds()),
	}, nil
}

func (s *MessageService) captchaBinding(scene int32) string {
	return fmt.Sprintf("%d:%s", scene, clientip.FromContext(s.c))
}

func (s *MessageService) VerifyCaptcha(req *message.VerifyCaptchaRequest) (*message.VerifyCaptchaResponse, error) {
	if !codeStore.Allow("captcha_verify:"+clientip.FromContext(s.c), 60, time.Minute) ||
		!codeStore.Verify("captcha_binding", req.CaptchaId, s.captchaBinding(int32(req.Scene))) ||
		!captcha.Verify(req.CaptchaId, req.Answer, true) {
		return nil, errno.AuthorizationFailedErr
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	if err := codeStore.Store("captcha_grant", token, s.captchaBinding(int32(req.Scene)), 2*time.Minute); err != nil {
		return nil, err
	}
	return &message.VerifyCaptchaResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg, VerifyToken: token, ExpireSeconds: 120}, nil
}

// SendCode issues a one-time verification code for the given scene, stores it in
// redis keyed by (scene, target), and delivers it over the requested channel
// (email or SMS). The stored code is later consumed by the matching verify step
// (e.g. the auth service's email/SMS code login for the LOGIN scene).
func (s *MessageService) SendCode(req *message.SendCodeRequest) (*message.SendCodeResponse, error) {
	req.Target = redis.NormalizeCodeTarget(req.Target)
	if req.Target == "" || len(req.Target) > 254 {
		return nil, errno.ParamErr
	}
	scene := sceneKey(req.Scene)
	if scene == "" {
		return nil, errno.ParamErr
	}
	if req.Channel != message.MessageChannel_MESSAGE_CHANNEL_EMAIL && req.Channel != message.MessageChannel_MESSAGE_CHANNEL_SMS {
		return nil, errno.ParamErr
	}
	if req.Channel == message.MessageChannel_MESSAGE_CHANNEL_EMAIL {
		address, err := mail.ParseAddress(req.Target)
		if err != nil || address.Address != req.Target {
			return nil, errno.ParamErr
		}
	} else {
		digits := strings.TrimPrefix(req.Target, "+")
		if len(digits) < 7 || len(digits) > 15 || strings.Trim(digits, "0123456789") != "" {
			return nil, errno.ParamErr
		}
	}
	if !codeStore.Allow("send:ip:"+clientip.FromContext(s.c), 20, time.Hour) ||
		!codeStore.Verify("captcha_grant", req.CaptchaVerifyToken, s.captchaBinding(int32(req.Scene))) ||
		!codeStore.Allow("send:account:"+req.Target, 10, time.Hour) ||
		!codeStore.Allow("send:scene:"+scene+":"+req.Target, 1, time.Minute) {
		return nil, errno.AuthorizationFailedErr
	}

	code, err := newVerificationCode()
	if err != nil {
		return nil, err
	}
	if err := codeStore.Store(scene, req.Target, code, codeTTL); err != nil {
		return nil, err
	}

	body := fmt.Sprintf("你的验证码是 %s，%d 分钟内有效。", code, int(codeTTL/time.Minute))
	switch req.Channel {
	case message.MessageChannel_MESSAGE_CHANNEL_EMAIL:
		if err := s.sendEmail(s.ctx, &email.Message{
			To:      []string{req.Target},
			Subject: "你的验证码",
			Text:    body,
		}); err != nil {
			codeStore.Discard(scene, req.Target, code)
			return nil, err
		}
	case message.MessageChannel_MESSAGE_CHANNEL_SMS:
		if err := sms.Send(s.ctx, &sms.Message{
			PhoneNumbers:  []string{req.Target},
			TemplateParam: map[string]string{"code": code},
			Content:       body,
		}); err != nil {
			codeStore.Discard(scene, req.Target, code)
			return nil, err
		}
	default:
		return nil, errno.ParamErr
	}

	return &message.SendCodeResponse{
		Code:              errno.SuccessCode,
		Message:           errno.SuccessMsg,
		ExpireSeconds:     int32(codeTTL / time.Second),
		RetryAfterSeconds: codeRetryAfterSeconds,
	}, nil
}

// sceneKey maps the proto MessageScene to the redis scene namespace. The LOGIN
// mapping ("login") must stay in sync with the auth service's login scene.
func sceneKey(scene message.MessageScene) string {
	switch scene {
	case message.MessageScene_MESSAGE_SCENE_LOGIN:
		return "login"
	case message.MessageScene_MESSAGE_SCENE_REGISTER:
		return "register"
	case message.MessageScene_MESSAGE_SCENE_BIND_MOBILE:
		return "bind_mobile"
	case message.MessageScene_MESSAGE_SCENE_BIND_EMAIL:
		return "bind_email"
	case message.MessageScene_MESSAGE_SCENE_RESET_PASSWORD:
		return "reset_password"
	case message.MessageScene_MESSAGE_SCENE_DELETE_ACCOUNT:
		return "delete_account"
	default:
		return ""
	}
}

// newVerificationCode returns a cryptographically random 6-digit code.
func newVerificationCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
