package message

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/authboot/authboot-server/biz/model/message"
	"github.com/authboot/authboot-server/biz/mw/captcha"
	"github.com/authboot/authboot-server/biz/mw/email"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/biz/mw/sms"
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
	ctx context.Context
	c   *app.RequestContext
}

// NewMessageService create message service
func NewMessageService(ctx context.Context, c *app.RequestContext) *MessageService {
	return &MessageService{ctx: ctx, c: c}
}

// CreateCaptcha generates a new image captcha. It returns the captcha id, the
// base64-encoded PNG image, and the remaining validity in seconds. The client
// submits the id together with the user's answer to VerifyCaptcha.
func (s *MessageService) CreateCaptcha(req *message.CreateCaptchaRequest) (*message.CreateCaptchaResponse, error) {
	id, b64s, err := captcha.Generate()
	if err != nil {
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

// SendCode issues a one-time verification code for the given scene, stores it in
// redis keyed by (scene, target), and delivers it over the requested channel
// (email or SMS). The stored code is later consumed by the matching verify step
// (e.g. the auth service's email/SMS code login for the LOGIN scene).
func (s *MessageService) SendCode(req *message.SendCodeRequest) (*message.SendCodeResponse, error) {
	if req.Target == "" {
		return nil, errno.ParamErr
	}
	scene := sceneKey(req.Scene)
	if scene == "" {
		return nil, errno.ParamErr
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
		if err := email.Send(s.ctx, &email.Message{
			To:      []string{req.Target},
			Subject: "你的验证码",
			Text:    body,
		}); err != nil {
			return nil, err
		}
	case message.MessageChannel_MESSAGE_CHANNEL_SMS:
		if err := sms.Send(s.ctx, &sms.Message{
			PhoneNumbers:  []string{req.Target},
			TemplateParam: map[string]string{"code": code},
			Content:       body,
		}); err != nil {
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
