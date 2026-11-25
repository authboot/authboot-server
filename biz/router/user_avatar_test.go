package router_test

import (
	"bytes"
	"encoding/json"
	"image"
	"image/png"
	"mime/multipart"
	"testing"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/cloudwego/hertz/pkg/app/server"
)

// avatarForm builds a multipart body with the given file content in the
// "avatar" field plus any extra plain form fields.
func avatarForm(t *testing.T, file []byte, fields map[string]string) (contentType, body string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for key, value := range fields {
		if err := w.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := w.CreateFormFile("avatar", "avatar.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(file); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return w.FormDataContentType(), b.String()
}

func pngBytes(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// uploadAvatar posts the multipart form and returns the HTTP status plus the
// business code (-1 when the response carries no JSON body).
func uploadAvatar(t *testing.T, h *server.Hertz, path, token, contentType, body string) (int, int) {
	t.Helper()
	status, raw := rawSecurityRequest(h, "POST", path, token, contentType, body)
	var result struct {
		Code *int `json:"code"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &result) != nil || result.Code == nil {
		return status, -1
	}
	return status, *result.Code
}

func assertAvatarsUntouched(t *testing.T) {
	t.Helper()
	var users []db.User
	if err := db.DB.Find(&users).Error; err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Avatar != "" {
			t.Fatalf("user %d avatar changed to %q", u.ID, u.Avatar)
		}
	}
}

func TestAdminUploadUserAvatarAuthorization(t *testing.T) {
	h := securityApp(t)
	if err := db.DB.Create(&db.User{ID: 3, OrganizationID: 2, Status: 1}).Error; err != nil {
		t.Fatal(err)
	}
	_, owner := newSession(t, "admin", 1, 1)
	_, endUser := newSession(t, "user", 1, 1)
	img := pngBytes(t)
	path := "/api/v1/admin/organizations/1/users/1/avatar"

	for _, tc := range []struct {
		name, path, token string
		fields            map[string]string
		status            int
	}{
		{"missing token", path, "", nil, 401},
		{"end-user token", path, endUser, nil, 401},
		// Account 1 is also a member of organization 2, but the token is scoped to 1.
		{"other organization", "/api/v1/admin/organizations/2/users/3/avatar", owner, nil, 403},
		{"query rebinds organization", path + "?organization_id=2", owner, nil, 403},
		{"form rebinds user", path, owner, map[string]string{"user_id": "2"}, 403},
		{"form rebinds organization", path, owner, map[string]string{"organization_id": "2"}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contentType, body := avatarForm(t, img, tc.fields)
			if status, code := uploadAvatar(t, h, tc.path, tc.token, contentType, body); status != tc.status {
				t.Fatalf("status=%d code=%d, want status %d", status, code, tc.status)
			}
			assertAvatarsUntouched(t)
		})
	}
}

func TestAdminUploadUserAvatarValidatesTargetAndImage(t *testing.T) {
	h := securityApp(t)
	if err := db.DB.Create(&db.User{ID: 3, OrganizationID: 2, Status: 1}).Error; err != nil {
		t.Fatal(err)
	}
	_, owner := newSession(t, "admin", 1, 1)
	img := pngBytes(t)

	t.Run("user of another organization", func(t *testing.T) {
		contentType, body := avatarForm(t, img, nil)
		status, code := uploadAvatar(t, h, "/api/v1/admin/organizations/1/users/3/avatar", owner, contentType, body)
		if status != 200 || code != errno.CrossOrganizationAccessErrCode {
			t.Fatalf("status=%d code=%d", status, code)
		}
	})

	path := "/api/v1/admin/organizations/1/users/1/avatar"
	t.Run("not an image", func(t *testing.T) {
		contentType, body := avatarForm(t, []byte(`<svg onload="alert(1)"/>`), nil)
		if status, code := uploadAvatar(t, h, path, owner, contentType, body); status != 200 || code != errno.ParamErrCode {
			t.Fatalf("status=%d code=%d", status, code)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		if status, code := uploadAvatar(t, h, path, owner, "application/json", `{}`); status != 200 || code != errno.ParamErrCode {
			t.Fatalf("status=%d code=%d", status, code)
		}
	})
	// The router tests run without object storage, so an authorized upload of a
	// valid image must fail closed instead of recording an avatar it never stored.
	t.Run("storage unavailable", func(t *testing.T) {
		contentType, body := avatarForm(t, img, map[string]string{"organization_id": "1", "user_id": "1"})
		status, code := uploadAvatar(t, h, path, owner, contentType, body)
		if status != 200 || code == errno.SuccessCode || code == errno.ParamErrCode || code == -1 {
			t.Fatalf("status=%d code=%d", status, code)
		}
	})
	assertAvatarsUntouched(t)
}
