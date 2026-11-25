package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Vector from the Alibaba Cloud RPC signature documentation.
func TestAliyunRPCSign(t *testing.T) {
	params := map[string]string{
		"Action": "DescribeRegions", "Version": "2014-05-26", "Format": "XML",
		"AccessKeyId": "testid", "SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0",
		"SignatureNonce": "3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf", "Timestamp": "2016-02-23T12:46:24Z",
	}
	if got := aliyunRPCSign("GET", params, "testsecret"); got != "OLeaidS1JvxuMvnyHOwuJ+uX5qY=" {
		t.Fatalf("signature = %s", got)
	}
}

func TestSplitAddress(t *testing.T) {
	addr, name := splitAddress(`"Acme" <no@x.io>`)
	if addr != "no@x.io" || name != "Acme" {
		t.Fatalf("%q %q", addr, name)
	}
	addr, name = splitAddress("no@x.io")
	if addr != "no@x.io" || name != "" {
		t.Fatalf("%q %q", addr, name)
	}
}

func TestAliyunDMSend(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, _ = url.ParseQuery(string(b))
		w.Write([]byte(`{"RequestId":"x","EnvId":"1"}`))
	}))
	defer srv.Close()
	s := NewAliyunDMSender(AliyunDMConfig{AccessKeyID: "k", AccessKeySecret: "s", SenderAddress: "a@b.c", SenderName: "Acme", Endpoint: srv.URL})
	if err := s.Send(context.Background(), &Message{To: []string{"u@v.w"}, Subject: "hi", Text: "body"}); err != nil {
		t.Fatal(err)
	}
	if got.Get("Action") != "SingleSendMail" || got.Get("AccountName") != "a@b.c" || got.Get("FromAlias") != "Acme" || got.Get("Signature") == "" {
		t.Fatalf("params: %v", got)
	}
}

func TestTencentSESSendReportsBusinessError(t *testing.T) {
	var body map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{"Response":{"Error":{"Code":"FailedOperation.SendEmailFail","Message":"bad"}}}`))
	}))
	defer srv.Close()
	s := NewTencentSESSender(TencentSESConfig{SecretID: "id", SecretKey: "key", Region: "ap-guangzhou", SenderAddress: "a@b.c", Endpoint: srv.URL})
	err := s.Send(context.Background(), &Message{To: []string{"u@v.w"}, Subject: "hi", HTML: "<b>x</b>"})
	if err == nil || !strings.Contains(err.Error(), "FailedOperation.SendEmailFail") {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(auth, "TC3-HMAC-SHA256 Credential=id/") || body["Simple"] == nil {
		t.Fatalf("auth=%q body=%v", auth, body)
	}
}

func TestTC3AuthorizationStable(t *testing.T) {
	now := time.Unix(1700000000, 0)
	a := tc3Authorization("id", "key", "ses", tencentSESHost, "sendemail", []byte(`{}`), now)
	b := tc3Authorization("id", "key", "ses", tencentSESHost, "sendemail", []byte(`{}`), now)
	if a != b || !strings.Contains(a, "2023-11-14/ses/tc3_request") {
		t.Fatalf("%s", a)
	}
}
