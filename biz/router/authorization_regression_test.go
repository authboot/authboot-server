package router_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/authboot/authboot-server/biz/dal/db"
	clientroute "github.com/authboot/authboot-server/biz/router/client"
	notificationroute "github.com/authboot/authboot-server/biz/router/notification"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
)

func rawSecurityRequest(h *server.Hertz, method, path, token, contentType, body string, stepup ...string) (int, []byte) {
	c := app.NewContext(0)
	c.Request.SetRequestURI(path)
	c.Request.Header.SetMethod(method)
	c.Request.Header.Set("Content-Type", contentType)
	c.Request.Header.Set("Authorization", "Bearer "+token)
	if len(stepup) > 0 {
		c.Request.Header.Set("X-Step-Up-Token", stepup[0])
	}
	c.Request.SetBodyString(body)
	c.Request.Header.SetContentLength(len(body))
	h.ServeHTTP(context.Background(), c)
	return c.Response.StatusCode(), append([]byte(nil), c.Response.Body()...)
}

func TestAuthorizedOrganizationMatchesDecodedRequest(t *testing.T) {
	for _, tc := range []struct {
		name, query, body, contentType string
		valid                          bool
	}{
		{"uppercase", "", `{"ORGANIZATION_ID":2}`, "", false},
		{"mixed", "", `{"Organization_Id":2}`, "", false},
		{"go_alias", "", `{"OrganizationId":2}`, "", false},
		{"duplicate", "", `{"organization_id":1,"organization_id":2}`, "", false},
		{"duplicate_case", "", `{"organization_id":1,"ORGANIZATION_ID":2}`, "", false},
		{"duplicate_reverse", "", `{"ORGANIZATION_ID":2,"organization_id":1}`, "", false},
		{"escaped_key", "", `{"\u004fRGANIZATION_ID":2}`, "", false},
		{"query_mismatch", "?organization_id=2", `{}`, "", false},
		{"query_duplicate", "?organization_id=1&organization_id=2", `{}`, "", false},
		{"query_body", "?organization_id=1", `{"ORGANIZATION_ID":2}`, "", false},
		{"form", "", "organization_id=2", "application/x-www-form-urlencoded", false},
		{"form_duplicate", "", "organization_id=1&organization_id=2", "application/x-www-form-urlencoded", false},
		{"valid", "", `{"organization_id":1}`, "", true},
		{"valid_uppercase", "?organization_id=1", `{"ORGANIZATION_ID":1}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := securityApp(t)
			rec, owner := newSession(t, "admin", 1, 1)
			contentType := tc.contentType
			if contentType == "" {
				contentType = "application/json"
			}
			grant, err := db.NewSecurityGrant(db.DB, db.SecurityGrant{Subject: "admin", AccountID: 1, OrganizationID: 1, SessionID: rec.SessionID, Scope: "organization:delete"}, time.Now(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			status, body := rawSecurityRequest(h, "DELETE", "/api/v1/admin/organizations/1"+tc.query, owner, contentType, tc.body, grant)
			var one, two db.Organization
			db.DB.First(&one, 1)
			db.DB.First(&two, 2)
			if two.Status != 1 {
				t.Fatalf("foreign organization changed: %d %s", status, body)
			}
			if status == 200 {
				// Duplicate/alias precedence may vary with the configured decoder.
				// Success is safe only if the actually authorized org was used.
				if one.Status != 2 {
					t.Fatalf("success did not use path scope: %s", body)
				}
			} else if status != 400 && status != 403 {
				t.Fatalf("unexpected status: %d %s", status, body)
			}
			if tc.valid && status != 200 {
				t.Fatalf("valid request rejected: %d %s", status, body)
			}
		})
	}
}

func TestNestedResourceCannotBeRebound(t *testing.T) {
	for _, body := range []string{
		`{"CLIENT_ID":2}`, `{"Client_Id":2}`, `{"client_id":1,"CLIENT_ID":2}`,
		`{"ORGANIZATION_ID":2,"CLIENT_ID":3}`, `{"client_id":2,"client_id":1}`, `{}`,
	} {
		t.Run(body, func(t *testing.T) {
			h := securityApp(t)
			clientroute.Register(h)
			if err := db.DB.AutoMigrate(&db.AppClient{}); err != nil {
				t.Fatal(err)
			}
			for _, row := range []db.AppClient{
				{ID: 1, OrganizationID: 1, Name: "path"}, {ID: 2, OrganizationID: 1, Name: "other"},
				{ID: 3, OrganizationID: 2, Name: "foreign"},
			} {
				if err := db.DB.Create(&row).Error; err != nil {
					t.Fatal(err)
				}
			}
			_, owner := newSession(t, "admin", 1, 1)
			status, response := rawSecurityRequest(h, "DELETE", "/api/v1/admin/organizations/1/clients/1", owner, "application/json", body)
			for _, id := range []int64{2, 3} {
				var count int64
				db.DB.Model(&db.AppClient{}).Where("id = ?", id).Count(&count)
				if count != 1 {
					t.Fatalf("non-path resource deleted: %d %s", status, response)
				}
			}
			if body == "{}" && status != 200 {
				t.Fatalf("valid request rejected: %d %s", status, response)
			}
		})
	}
}

func TestNotificationRoutesAndAccountOwnership(t *testing.T) {
	h := securityApp(t)
	notificationroute.Register(h)
	if err := db.DB.AutoMigrate(&db.Notification{}); err != nil {
		t.Fatal(err)
	}
	db.INotificationDAO = db.NewNotificationDAO(db.DB)
	for _, n := range []db.Notification{
		{ID: 1, UserID: 1, Title: "mine", Status: 1},
		{ID: 2, UserID: 2, Title: "foreign", Status: 1},
		{ID: 3, UserID: 1, Title: "mine too", Status: 1},
	} {
		if err := db.DB.Create(&n).Error; err != nil {
			t.Fatal(err)
		}
	}
	_, access := newSession(t, "admin", 1, 0)
	success := func(method, path, body string) map[string]interface{} {
		t.Helper()
		status, raw := rawSecurityRequest(h, method, path, access, "application/json", body)
		var result map[string]interface{}
		if json.Unmarshal(raw, &result) != nil || status != 200 || result["code"] != float64(0) {
			t.Fatalf("self-service failed: %s %s: %d %s", method, path, status, raw)
		}
		return result
	}
	list := success("GET", "/api/v1/admin/notifications?user_id=2", `{}`)
	if list["total"] != float64(2) {
		t.Fatal("list ownership", list)
	}
	success("GET", "/api/v1/admin/notifications/check-new", `{}`)
	success("GET", "/api/v1/admin/notifications/1", `{}`)
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/v1/admin/notifications/2", `{}`},
		{"POST", "/api/v1/admin/notifications/2/read", `{}`},
		{"DELETE", "/api/v1/admin/notifications/2", `{}`},
	} {
		status, raw := rawSecurityRequest(h, tc.method, tc.path, access, "application/json", tc.body)
		var result map[string]interface{}
		_ = json.Unmarshal(raw, &result)
		if status == 200 && result["code"] == float64(0) {
			t.Fatalf("foreign operation accepted: %s", raw)
		}
	}
	success("POST", "/api/v1/admin/notifications/1/read", `{}`)
	// Explicit path tags may override aliases rather than reject them.
	// In either case the foreign notification must remain unchanged.
	rawSecurityRequest(h, "POST", "/api/v1/admin/notifications/1/read", access, "application/json", `{"ID":2}`)
	rawSecurityRequest(h, "DELETE", "/api/v1/admin/notifications/3", access, "application/json", `{"id":3,"ID":2}`)
	success("POST", "/api/v1/admin/notifications/read-all", `{"user_id":2}`)
	success("DELETE", "/api/v1/admin/notifications/1", `{}`)
	success("DELETE", "/api/v1/admin/notifications", `{"USER_ID":2}`)
	var foreign db.Notification
	if db.DB.First(&foreign, 2).Error != nil || foreign.Status != 1 {
		t.Fatal("foreign notification modified")
	}
	var mine int64
	db.DB.Model(&db.Notification{}).Where("user_id = 1").Count(&mine)
	if mine != 0 {
		t.Fatal("self delete-all did not execute")
	}
}
