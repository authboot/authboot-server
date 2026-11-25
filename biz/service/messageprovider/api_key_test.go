package messageprovider

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/email"
)

func TestEncryptedResendKeyPreview(t *testing.T) {
	t.Setenv("EMAIL_CONFIG_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	sealed, err := email.Encrypt([]byte(`{"api_key":"re_abc_test_only","from":"test@example.org"}`))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("re_abc_test_only")) {
		t.Fatal("stored config contains plaintext key")
	}
	view, err := toProviderConfig(&db.MessageProviderConfig{Provider: "resend", Channel: "email", Config: sealed})
	if err != nil {
		t.Fatal(err)
	}
	if view.Settings["api_key"] != "re_abc****" || view.Settings["from"] != "test@example.org" {
		t.Fatal("unexpected provider preview")
	}
	if apiKeyPreview("short") != "****" {
		t.Fatal("short key should be fully masked")
	}
}
