package user

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/authboot/authboot-server/biz/dal/db"
	model "github.com/authboot/authboot-server/biz/model/user"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
)

func TestValidateAvatar(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	for _, format := range []string{"png", "jpeg", "gif"} {
		t.Run(format, func(t *testing.T) {
			var b bytes.Buffer
			var err error
			switch format {
			case "png":
				err = png.Encode(&b, img)
			case "jpeg":
				err = jpeg.Encode(&b, img, nil)
			case "gif":
				err = gif.Encode(&b, img, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := validateAvatar(b.Bytes())
			if err != nil || got != format {
				t.Fatalf("format=%q err=%v", got, err)
			}
			if _, err := validateAvatar(b.Bytes()[:b.Len()/2]); err == nil {
				t.Fatal("accepted truncated image")
			}
		})
	}
	var large bytes.Buffer
	if err := png.Encode(&large, image.NewGray(image.Rect(0, 0, 4001, 4000))); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"empty": nil, "svg": []byte(`<svg onload="alert(1)"/>`),
		"oversized": make([]byte, maxAvatarBytes+1), "pixels": large.Bytes(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateAvatar(data); !errors.Is(err, errno.ParamErr) {
				t.Fatalf("expected parameter error, got %v", err)
			}
		})
	}
}

func TestUploadAvatarRequiresAuthenticatedOrganization(t *testing.T) {
	c := app.NewContext(0)
	s := &UserService{ctx: context.Background(), c: c}
	for _, userID := range []interface{}{nil, "1", int64(1)} {
		c.Set(jwt.CtxKeyUserID, userID)
		if _, err := s.UploadMyAvatar(&model.UploadMyAvatarRequest{}); !errors.Is(err, errno.AuthorizationFailedErr) {
			t.Fatalf("expected authentication failure before accessing storage, got %v", err)
		}
	}
}

type existingIdentityStore struct {
	identityStore
	identity *db.UserIdentity
}

type concurrentIdentityStore struct {
	identityStore
	err error
}

func (s concurrentIdentityStore) QueryIdentity(int64, string, string) (*db.UserIdentity, error) {
	return nil, errno.UserIsNotExistErr
}

func (s concurrentIdentityStore) CreateIdentity(*db.UserIdentity) (int64, error) {
	return 0, s.err
}

func TestBindConcurrentDuplicateReturnsConflict(t *testing.T) {
	for _, err := range []error{gorm.ErrDuplicatedKey, &mysql.MySQLError{Number: 1062}} {
		s := &IdentityService{userIdentityDAO: concurrentIdentityStore{err: err}}
		_, got := s.bind(&db.User{ID: 10, OrganizationID: 2}, "email", "user@example.com")
		if !errors.Is(got, errno.IdentityAlreadyExistErr) {
			t.Fatalf("expected identity conflict, got %v", got)
		}
	}
}

func (s existingIdentityStore) QueryIdentity(org int64, kind, value string) (*db.UserIdentity, error) {
	return s.identity, nil
}

func TestBindExistingIdentityNeverTransfersOwnership(t *testing.T) {
	for _, owner := range []int64{10, 20} {
		identity := &db.UserIdentity{ID: 1, OrganizationID: 2, UserID: owner}
		s := &IdentityService{userIdentityDAO: existingIdentityStore{identity: identity}}
		resp, err := s.bind(&db.User{ID: 10, OrganizationID: 2}, "email", "user@example.com")
		if owner == 10 {
			if err != nil || resp.Identity.UserId != owner {
				t.Fatalf("idempotent bind: %v", err)
			}
		} else if !errors.Is(err, errno.IdentityAlreadyExistErr) {
			t.Fatalf("expected conflict, got %v", err)
		}
		if identity.UserID != owner {
			t.Fatal("identity ownership changed")
		}
	}
}
