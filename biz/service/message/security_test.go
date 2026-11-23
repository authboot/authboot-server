package message

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	model "github.com/authboot/authboot-server/biz/model/message"
	"github.com/authboot/authboot-server/biz/mw/email"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/cloudwego/hertz/pkg/app"
)

func TestSendCodeSecurity(t *testing.T) {
	for _, scenario := range []string{"captcha", "cooldown", "account", "ip", "delivery_failure"} {
		t.Run(scenario, func(t *testing.T) {
			r := miniredis.RunT(t)
			t.Setenv("REDIS_ADDR", r.Addr())
			t.Setenv("REDIS_PASSWORD", "")
			redis.InitRedis()
			s := NewMessageService(context.Background(), app.NewContext(0))
			deliveries := 0
			code := ""
			s.sendEmail = func(_ context.Context, m *email.Message) error {
				deliveries++
				code = regexp.MustCompile(`[0-9]{6}`).FindString(m.Text)
				if scenario == "delivery_failure" {
					return errors.New("test delivery failure")
				}
				return nil
			}
			send := func(i int, target string, grant bool) error {
				token := fmt.Sprintf("grant-%d", i)
				if grant {
					if err := codeStore.Store("captcha_grant", token, s.captchaBinding(1), time.Minute); err != nil {
						t.Fatal(err)
					}
				}
				_, err := s.SendCode(&model.SendCodeRequest{Target: target, Channel: model.MessageChannel_MESSAGE_CHANNEL_EMAIL, Scene: model.MessageScene_MESSAGE_SCENE_LOGIN, CaptchaVerifyToken: token})
				return err
			}
			switch scenario {
			case "captcha":
				if send(1, "user@example.test", false) == nil || deliveries != 0 {
					t.Fatal("captcha bypass")
				}
			case "cooldown":
				if err := send(1, "User@example.test", true); err != nil {
					t.Fatal(err)
				}
				if send(2, "user@example.test", true) == nil || deliveries != 1 {
					t.Fatal("resend cooldown bypass")
				}
				if !codeStore.Verify("login", "USER@example.test", code) || codeStore.Verify("login", "user@example.test", code) {
					t.Fatal("code not single use")
				}
			case "account":
				for i := 0; i < 10; i++ {
					if err := send(i, "user@example.test", true); err != nil {
						t.Fatal(i, err)
					}
					r.FastForward(time.Minute)
				}
				if send(11, "user@example.test", true) == nil || deliveries != 10 {
					t.Fatal("account rate bypass")
				}
			case "ip":
				for i := 0; i < 20; i++ {
					if err := send(i, fmt.Sprintf("user%d@example.test", i), true); err != nil {
						t.Fatal(i, err)
					}
				}
				if send(21, "extra@example.test", true) == nil || deliveries != 20 {
					t.Fatal("IP rate bypass")
				}
			case "delivery_failure":
				if send(1, "user@example.test", true) == nil {
					t.Fatal("failed delivery accepted")
				}
				if code == "" || codeStore.Verify("login", "user@example.test", code) {
					t.Fatal("failed delivery code remains valid")
				}
			}
		})
	}
}
