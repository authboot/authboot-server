package user

import (
	"context"
	"errors"
	"testing"

	"github.com/authboot/authboot-server/biz/dal/db"
	model "github.com/authboot/authboot-server/biz/model/user"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/pkg/errno"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
)

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

func TestUploadUserAvatarRequiresOrganizationAndUser(t *testing.T) {
	s := &UserService{ctx: context.Background(), c: app.NewContext(0)}
	for _, req := range []*model.GetUserRequest{
		{}, {OrganizationId: 1}, {UserId: 1},
	} {
		if _, err := s.UploadUserAvatar(req); !errors.Is(err, errno.ParamErr) {
			t.Fatalf("expected parameter error before any lookup, got %v", err)
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
