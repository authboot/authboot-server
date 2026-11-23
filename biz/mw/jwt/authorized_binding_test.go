package jwt

import (
	"fmt"
	"strings"
	"testing"

	"github.com/authboot/authboot-server/biz/model/address"
	"github.com/authboot/authboot-server/biz/model/client"
	"github.com/authboot/authboot-server/biz/model/invitation"
	"github.com/authboot/authboot-server/biz/model/membership"
	"github.com/authboot/authboot-server/biz/model/notification"
	"github.com/authboot/authboot-server/biz/model/oauth"
	"github.com/authboot/authboot-server/biz/model/organization"
	"github.com/authboot/authboot-server/biz/model/session"
	"github.com/authboot/authboot-server/biz/model/user"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/route/param"
)

func TestFinalBoundSelectorsAcrossResourceModels(t *testing.T) {
	for _, tc := range []struct {
		key         string
		makeRequest func() (interface{}, func() string)
	}{
		{"organization_id", func() (interface{}, func() string) {
			r := &organization.DeleteOrganizationRequest{}
			return r, func() string { return fmt.Sprint(r.OrganizationId) }
		}},
		{"user_id", func() (interface{}, func() string) {
			r := &user.GetUserRequest{OrganizationId: 1}
			return r, func() string { return fmt.Sprint(r.UserId) }
		}},
		{"client_id", func() (interface{}, func() string) {
			r := &client.DeleteClientRequest{OrganizationId: 1}
			return r, func() string { return fmt.Sprint(r.ClientId) }
		}},
		{"membership_id", func() (interface{}, func() string) {
			r := &membership.GetMembershipRequest{}
			return r, func() string { return fmt.Sprint(r.MembershipId) }
		}},
		{"address_id", func() (interface{}, func() string) {
			r := &address.AdminDeleteAddressRequest{OrganizationId: 1, UserId: 1}
			return r, func() string { return fmt.Sprint(r.AddressId) }
		}},
		{"invitation_id", func() (interface{}, func() string) {
			r := &invitation.GetInvitationRequest{}
			return r, func() string { return fmt.Sprint(r.InvitationId) }
		}},
		{"account_id", func() (interface{}, func() string) {
			r := &session.ListAdminSessionsRequest{}
			return r, func() string { return fmt.Sprint(r.AccountId) }
		}},
		{"session_id", func() (interface{}, func() string) {
			r := &session.GetAdminSessionRequest{}
			return r, func() string { return r.SessionId }
		}},
		{"provider", func() (interface{}, func() string) {
			r := &oauth.GetOAuthConfigRequest{OrganizationId: 1}
			return r, func() string { return r.Provider }
		}},
		{"id", func() (interface{}, func() string) {
			r := &notification.GetNotificationRequest{}
			return r, func() string { return fmt.Sprint(r.Id) }
		}},
	} {
		for _, source := range []string{"uppercase", "duplicate", "query", "form", "valid", "path_only"} {
			t.Run(tc.key+"/"+source, func(t *testing.T) {
				c := app.NewContext(0)
				c.Params = param.Params{{Key: tc.key, Value: "1"}, {Key: "organization_id", Value: "1"}}
				c.Request.Header.SetMethod("POST")
				c.Request.Header.Set("Content-Type", "application/json")
				body := fmt.Sprintf(`{%q:1}`, tc.key)
				quote := func(v string) string {
					if tc.key == "session_id" || tc.key == "provider" {
						return `"` + v + `"`
					}
					return v
				}
				switch source {
				case "uppercase":
					body = fmt.Sprintf(`{%q:%s}`, strings.ToUpper(tc.key), quote("2"))
				case "duplicate":
					body = fmt.Sprintf(`{%q:%s,%q:%s}`, tc.key, quote("1"), strings.ToUpper(tc.key), quote("2"))
				case "query":
					c.Request.SetRequestURI("/?" + tc.key + "=2")
					body = "{}"
				case "form":
					c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					body = tc.key + "=2"
				case "valid":
					body = fmt.Sprintf(`{%q:%s}`, tc.key, quote("1"))
				case "path_only":
					body = "{}"
				}
				c.Request.SetBodyString(body)
				c.Request.Header.SetContentLength(len(body))
				installAuthorizedBinding(c)
				obj, actual := tc.makeRequest()
				err := c.BindAndValidate(obj)
				if err == nil && actual() != "1" {
					t.Fatalf("bound unauthorized selector: %s", actual())
				}
				if (source == "valid" || source == "path_only") && err != nil {
					t.Fatal("valid request rejected:", err)
				}
			})
		}
	}
}
