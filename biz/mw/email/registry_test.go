package email

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"testing"
)

type stubSender struct {
	name string
	err  error
	hits int
}

func (s *stubSender) Name() string { return s.name }
func (s *stubSender) Send(context.Context, *Message) error {
	s.hits++
	return s.err
}

func TestFailoverSender(t *testing.T) {
	primary := &stubSender{name: "p", err: errors.New("down")}
	fallback := &stubSender{name: "f"}
	f := &failoverSender{senders: []Sender{primary, fallback}}
	if err := f.Send(context.Background(), &Message{}); err != nil {
		t.Fatalf("fallback should succeed: %v", err)
	}
	if primary.hits != 1 || fallback.hits != 1 {
		t.Fatalf("hits p=%d f=%d", primary.hits, fallback.hits)
	}

	fallback.err = errors.New("also down")
	if err := f.Send(context.Background(), &Message{}); err == nil {
		t.Fatal("all failing should error")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fallback.hits = 0
	_ = f.Send(ctx, &Message{})
	if fallback.hits != 0 {
		t.Fatal("cancelled ctx should stop after the first provider")
	}
}

func TestCatalogAndBuild(t *testing.T) {
	ids := map[string]bool{}
	for _, d := range Catalog() {
		ids[d.ID] = true
	}
	for _, id := range []string{"resend", "smtp", "aliyun_dm", "tencent_ses"} {
		if !ids[id] {
			t.Fatalf("catalog missing %s: %v", id, ids)
		}
	}
	if _, err := Build("aliyun_dm", map[string]string{"access_key_id": "k", "access_key_secret": "s", "sender_address": "a@b.c"}); err != nil {
		t.Fatalf("aliyun_dm build: %v", err)
	}
	if _, err := Build("tencent_ses", map[string]string{"secret_id": "k", "secret_key": "s", "sender_address": "a@b.c"}); err == nil {
		t.Fatal("tencent_ses without region should fail")
	}
	if _, err := Build("tencent_ses", map[string]string{"secret_id": "k", "secret_key": "s", "region": "ap-guangzhou", "sender_address": "a@b.c", "template_id": "x"}); err == nil {
		t.Fatal("non-numeric template_id should fail")
	}

	if _, err := Build("resend", map[string]string{"from": "a@b.c"}); err == nil {
		t.Fatal("resend without api_key should fail validation")
	}
	s, err := Build("resend", map[string]string{"api_key": "re_x", "from": "a@b.c"})
	if err != nil || s.Name() != "resend" {
		t.Fatalf("resend build: %v %v", s, err)
	}

	if _, err := Build("smtp", map[string]string{"host": "h", "from": "a@b.c", "port": "abc"}); err == nil {
		t.Fatal("non-numeric port should fail")
	}
	if _, err := Build("nope", nil); err == nil {
		t.Fatal("unknown provider should fail")
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv(envConfigKey, base64.StdEncoding.EncodeToString(key))

	sealed, err := Encrypt([]byte(`{"api_key":"re_x"}`))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(sealed)
	if err != nil || string(plain) != `{"api_key":"re_x"}` {
		t.Fatalf("round trip: %q %v", plain, err)
	}

	t.Setenv(envConfigKey, "")
	if _, err := Encrypt([]byte("x")); err == nil {
		t.Fatal("encrypt without key must fail closed")
	}
}

func TestSMTPTenantCheckRejectsPrivate(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1"} {
		if isPublicIP(net.ParseIP(ip)) {
			t.Errorf("%s should not be public", ip)
		}
	}
	if !isPublicIP(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 should be public")
	}
	if err := checkSMTPTarget("localhost", 587); err == nil {
		t.Error("localhost must be rejected")
	}
	if err := checkSMTPTarget("example.com", 8080); err == nil {
		t.Error("port 8080 must be rejected")
	}
}

func TestSenderForFallsBackToDefault(t *testing.T) {
	prev := defaultSender
	defer func() { defaultSender = prev }()
	defaultSender, _ = Build("resend", map[string]string{"api_key": "k", "from": "a@b.c"})

	// orgID 0 and a nil DAO (no database in unit tests) both resolve to default.
	if got := SenderFor(context.Background(), 0); got != defaultSender {
		t.Fatal("org 0 should use default sender")
	}
	if got := SenderFor(context.Background(), 42); got != defaultSender {
		t.Fatal("without DAO should use default sender")
	}
}
