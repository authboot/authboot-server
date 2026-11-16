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

// AliyunConfig holds the credentials for the 阿里云 SMS (Dysmsapi) adapter.
type AliyunConfig struct {
	AccessKeyID     string // 阿里云 AccessKey ID
	AccessKeySecret string // 阿里云 AccessKey Secret
	RegionID        string // default "cn-hangzhou"
	Endpoint        string // default "dysmsapi.aliyuncs.com"
	// SignName is the default 短信签名 used when Message.SignName is empty.
	SignName string
	// Timeout bounds the HTTP request.
	Timeout time.Duration
}

// aliyunSender implements Sender against the 阿里云 Dysmsapi SendSms RPC API,
// signing requests with the documented HMAC-SHA1 RPC signature scheme. It uses
// only the standard library, so no vendor SDK dependency is introduced.
type aliyunSender struct {
	cfg    AliyunConfig
	client *http.Client
}

// NewAliyunSender builds an 阿里云-backed Sender.
func NewAliyunSender(cfg AliyunConfig) Sender {
	if cfg.RegionID == "" {
		cfg.RegionID = "cn-hangzhou"
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "dysmsapi.aliyuncs.com"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &aliyunSender{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

func (s *aliyunSender) Name() string { return "aliyun" }

func (s *aliyunSender) Send(ctx context.Context, msg *Message) error {
	if err := msg.validate(); err != nil {
		return err
	}

	signName := msg.SignName
	if signName == "" {
		signName = s.cfg.SignName
	}
	if signName == "" {
		return fmt.Errorf("sms/aliyun: no SignName (set Message.SignName or AliyunConfig.SignName)")
	}
	if msg.TemplateCode == "" {
		return fmt.Errorf("sms/aliyun: TemplateCode is required")
	}

	nonce, err := signatureNonce()
	if err != nil {
		return fmt.Errorf("sms/aliyun: nonce: %w", err)
	}

	// System + business parameters for the SendSms action.
	params := map[string]string{
		"AccessKeyId":      s.cfg.AccessKeyID,
		"Action":           "SendSms",
		"Format":           "JSON",
		"RegionId":         s.cfg.RegionID,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   nonce,
		"SignatureVersion": "1.0",
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version":          "2017-05-25",
		"PhoneNumbers":     strings.Join(msg.PhoneNumbers, ","),
		"SignName":         signName,
		"TemplateCode":     msg.TemplateCode,
	}
	if len(msg.TemplateParam) > 0 {
		b, err := json.Marshal(msg.TemplateParam)
		if err != nil {
			return fmt.Errorf("sms/aliyun: marshal TemplateParam: %w", err)
		}
		params["TemplateParam"] = string(b)
	}

	params["Signature"] = sign("GET", params, s.cfg.AccessKeySecret)

	reqURL := "https://" + s.cfg.Endpoint + "/?" + canonicalQuery(params)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("sms/aliyun: build request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sms/aliyun: request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var out struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestId string `json:"RequestId"`
		BizId     string `json:"BizId"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("sms/aliyun: decode response (status %d): %s", resp.StatusCode, string(body))
	}
	if out.Code != "OK" {
		return fmt.Errorf("sms/aliyun: send failed: code=%s message=%s requestId=%s", out.Code, out.Message, out.RequestId)
	}
	return nil
}

// sign builds the 阿里云 RPC HMAC-SHA1 signature over the sorted parameters.
func sign(method string, params map[string]string, secret string) string {
	stringToSign := method + "&" + percentEncode("/") + "&" + percentEncode(canonicalQuery(params))
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// canonicalQuery renders params sorted by key as k=percentEncode(v)&... .
func canonicalQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, percentEncode(k)+"="+percentEncode(params[k]))
	}
	return strings.Join(parts, "&")
}

// percentEncode applies RFC 3986 encoding as required by the 阿里云 signature
// algorithm (space -> %20, * -> %2A, %7E -> ~).
func percentEncode(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	e = strings.ReplaceAll(e, "*", "%2A")
	e = strings.ReplaceAll(e, "%7E", "~")
	return e
}

// signatureNonce returns a random hex nonce for request de-duplication.
func signatureNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
