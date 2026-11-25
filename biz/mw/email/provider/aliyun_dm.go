/*
 * Copyright 2023 CloudWeGo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package provider

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AliyunDMConfig holds the credentials for Alibaba Cloud DirectMail (邮件推送).
type AliyunDMConfig struct {
	AccessKeyID     string
	AccessKeySecret string
	// Region selects the API endpoint, e.g. cn-hangzhou (dm.aliyuncs.com),
	// ap-southeast-1 (dm.ap-southeast-1.aliyuncs.com). Empty = cn-hangzhou.
	Region string
	// SenderAddress is a sender address already verified in DirectMail
	// (AccountName). Used when Message.From is empty.
	SenderAddress string
	// SenderName is the display name (FromAlias). Optional.
	SenderName string
	// Endpoint overrides the API endpoint derived from Region.
	Endpoint string
	Timeout  time.Duration
}

type aliyunDMSender struct {
	cfg    AliyunDMConfig
	client *http.Client
}

// NewAliyunDMSender builds a DirectMail-backed Sender.
func NewAliyunDMSender(cfg AliyunDMConfig) Sender {
	if cfg.Endpoint == "" {
		cfg.Endpoint = aliyunDMEndpoint(cfg.Region)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &aliyunDMSender{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout}}
}

func aliyunDMEndpoint(region string) string {
	region = strings.TrimSpace(region)
	if region == "" || region == "cn-hangzhou" {
		return "https://dm.aliyuncs.com"
	}
	return fmt.Sprintf("https://dm.%s.aliyuncs.com", region)
}

func (s *aliyunDMSender) Name() string { return "aliyun_dm" }

func (s *aliyunDMSender) Send(ctx context.Context, msg *Message) error {
	if err := msg.validate(); err != nil {
		return err
	}
	if s.cfg.AccessKeyID == "" || s.cfg.AccessKeySecret == "" {
		return fmt.Errorf("email/aliyun_dm: AccessKeyID and AccessKeySecret are required")
	}
	account, alias := s.cfg.SenderAddress, s.cfg.SenderName
	if msg.From != "" {
		account, alias = splitAddress(msg.From)
	}
	if account == "" {
		return fmt.Errorf("email/aliyun_dm: no sender address (set Message.From or AliyunDMConfig.SenderAddress)")
	}
	if len(msg.Cc) > 0 || len(msg.Bcc) > 0 {
		return fmt.Errorf("email/aliyun_dm: Cc/Bcc are not supported by SingleSendMail")
	}

	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("email/aliyun_dm: nonce: %w", err)
	}
	params := map[string]string{
		"Action":           "SingleSendMail",
		"Version":          "2015-11-23",
		"Format":           "JSON",
		"AccessKeyId":      s.cfg.AccessKeyID,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"SignatureNonce":   hex.EncodeToString(nonce),
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"AccountName":      account,
		"AddressType":      "1",
		"ReplyToAddress":   "false",
		"ToAddress":        strings.Join(msg.To, ","),
		"Subject":          msg.Subject,
	}
	if alias != "" {
		params["FromAlias"] = alias
	}
	if msg.HTML != "" {
		params["HtmlBody"] = msg.HTML
	}
	if msg.Text != "" {
		params["TextBody"] = msg.Text
	}
	if msg.ReplyTo != "" {
		params["ReplyAddress"] = msg.ReplyTo
	}
	params["Signature"] = aliyunRPCSign(http.MethodPost, params, s.cfg.AccessKeySecret)

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("email/aliyun_dm: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("email/aliyun_dm: request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		}
		if json.Unmarshal(respBody, &e) == nil && e.Code != "" {
			return fmt.Errorf("email/aliyun_dm: send failed (status %d): %s: %s", resp.StatusCode, e.Code, e.Message)
		}
		return fmt.Errorf("email/aliyun_dm: send failed (status %d): %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// aliyunRPCSign implements the Alibaba Cloud RPC-style signature (HMAC-SHA1
// over the canonicalized query string). params must not yet contain Signature.
func aliyunRPCSign(method string, params map[string]string, secret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canon strings.Builder
	for i, k := range keys {
		if i > 0 {
			canon.WriteByte('&')
		}
		canon.WriteString(aliyunPercentEncode(k))
		canon.WriteByte('=')
		canon.WriteString(aliyunPercentEncode(params[k]))
	}
	stringToSign := method + "&" + aliyunPercentEncode("/") + "&" + aliyunPercentEncode(canon.String())
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// aliyunPercentEncode is RFC 3986 encoding as required by the Aliyun spec.
func aliyunPercentEncode(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	e = strings.ReplaceAll(e, "*", "%2A")
	e = strings.ReplaceAll(e, "%7E", "~")
	return e
}

// splitAddress parses "Name <addr>" into (addr, name); a bare address yields
// an empty name.
func splitAddress(from string) (addr, name string) {
	from = strings.TrimSpace(from)
	lt := strings.LastIndex(from, "<")
	gt := strings.LastIndex(from, ">")
	if lt >= 0 && gt > lt {
		return strings.TrimSpace(from[lt+1 : gt]), strings.Trim(strings.TrimSpace(from[:lt]), `"`)
	}
	return from, ""
}
