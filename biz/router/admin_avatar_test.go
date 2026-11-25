package router_test

import (
	"testing"

	"github.com/authboot/authboot-server/biz/dal/db"
	adminroute "github.com/authboot/authboot-server/biz/router/admin"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/cloudwego/hertz/pkg/app/server"
)

const adminAvatarPath = "/api/v1/admin/me/avatar"

func adminAvatarApp(t *testing.T) *server.Hertz {
	t.Helper()
	h := securityApp(t)
	adminroute.Register(h)
	return h
}

func assertAdminAvatarsUntouched(t *testing.T) {
	t.Helper()
	var admins []db.AdminUser
	if err := db.DB.Find(&admins).Error; err != nil {
		t.Fatal(err)
	}
	for _, a := range admins {
		if a.Avatar != "" {
			t.Fatalf("admin %d avatar changed to %q", a.ID, a.Avatar)
		}
	}
}

func TestAdminUploadMyAvatarRequiresAdminSession(t *testing.T) {
	h := adminAvatarApp(t)
	_, endUser := newSession(t, "user", 1, 1)
	contentType, body := avatarForm(t, pngBytes(t), nil)

	for name, token := range map[string]string{
		"missing token":  "",
		"end-user token": endUser,
		"garbage token":  "not-a-token",
	} {
		t.Run(name, func(t *testing.T) {
			if status, code := uploadAvatar(t, h, adminAvatarPath, token, contentType, body); status != 401 {
				t.Fatalf("status=%d code=%d, want status 401", status, code)
			}
			assertAdminAvatarsUntouched(t)
		})
	}
}

func TestAdminUploadMyAvatarValidatesImage(t *testing.T) {
	h := adminAvatarApp(t)
	// A plain member is enough: the avatar is self-service, not an organization resource.
	_, member := newSession(t, "admin", 3, 1)

	t.Run("not an image", func(t *testing.T) {
		contentType, body := avatarForm(t, []byte(`<svg onload="alert(1)"/>`), nil)
		if status, code := uploadAvatar(t, h, adminAvatarPath, member, contentType, body); status != 200 || code != errno.ParamErrCode {
			t.Fatalf("status=%d code=%d", status, code)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		if status, code := uploadAvatar(t, h, adminAvatarPath, member, "application/json", `{}`); status != 200 || code != errno.ParamErrCode {
			t.Fatalf("status=%d code=%d", status, code)
		}
	})
	// The router tests run without object storage, so a valid image must fail
	// closed instead of recording an avatar that was never stored. Form fields
	// naming another account must not matter either: the target is the token's.
	t.Run("storage unavailable", func(t *testing.T) {
		contentType, body := avatarForm(t, pngBytes(t), map[string]string{"id": "1", "user_id": "1"})
		status, code := uploadAvatar(t, h, adminAvatarPath, member, contentType, body)
		if status != 200 || code == errno.SuccessCode || code == errno.ParamErrCode || code == -1 {
			t.Fatalf("status=%d code=%d", status, code)
		}
	})
	assertAdminAvatarsUntouched(t)
}
