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
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	tencentSESHost    = "ses.tencentcloudapi.com"
	tencentSESService = "ses"
	tencentSESVersion = "2020-10-02"
)

// TencentSESConfig holds the credentials for Tencent Cloud Simple Email
// Service (邮件推送).
type TencentSESConfig struct {
	SecretID  string
	SecretKey string
	// Region, e.g. ap-guangzhou / ap-hongkong. Required by the API.
	Region string
	// SenderAddress is a verified sender address; used when Message.From is
	// empty. May include a display name: "Acme <noreply@mail.example.com>".
	SenderAddress string
	// TemplateID, when non-zero, sends through an approved template with
	// TemplateData {"subject","html","text"}; otherwise the Simple body is used
	// (only available on accounts/regions that allow free-form content).
	TemplateID int64
	// Endpoint overrides the API URL; defaults to https://ses.tencentcloudapi.com.
	Endpoint string
	Timeout  time.Duration
}

type tencentSESSender struct {
	cfg    TencentSESConfig
	client *http.Client
}

// NewTencentSESSender builds a Tencent SES-backed Sender.
func NewTencentSESSender(cfg TencentSESConfig) Sender {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://" + tencentSESHost
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &tencentSESSender{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout}}
}

func (s *tencentSESSender) Name() string { return "tencent_ses" }

type tencentSendEmailRequest struct {
	FromEmailAddress string   `json:"FromEmailAddress"`
	Destination      []string `json:"Destination"`
	Subject          string   `json:"Subject"`
	ReplyToAddresses string   `json:"ReplyToAddresses,omitempty"`
	Cc               []string `json:"Cc,omitempty"`
	Bcc              []string `json:"Bcc,omitempty"`
	Template         *struct {
		TemplateID   int64  `json:"TemplateID"`
		TemplateData string `json:"TemplateData"`
	} `json:"Template,omitempty"`
	Simple *struct {
		Html string `json:"Html,omitempty"`
		Text string `json:"Text,omitempty"`
	} `json:"Simple,omitempty"`
}

func (s *tencentSESSender) Send(ctx context.Context, msg *Message) error {
	if err := msg.validate(); err != nil {
		return err
	}
	if s.cfg.SecretID == "" || s.cfg.SecretKey == "" {
		return fmt.Errorf("email/tencent_ses: SecretID and SecretKey are required")
	}
	if s.cfg.Region == "" {
		return fmt.Errorf("email/tencent_ses: Region is required")
	}
	from := msg.From
	if from == "" {
		from = s.cfg.SenderAddress
	}
	if from == "" {
		return fmt.Errorf("email/tencent_ses: no sender address (set Message.From or TencentSESConfig.SenderAddress)")
	}

	payload := tencentSendEmailRequest{
		FromEmailAddress: from,
		Destination:      msg.To,
		Subject:          msg.Subject,
		ReplyToAddresses: msg.ReplyTo,
		Cc:               msg.Cc,
		Bcc:              msg.Bcc,
	}
	if s.cfg.TemplateID > 0 {
		data, err := json.Marshal(map[string]string{"subject": msg.Subject, "html": msg.HTML, "text": msg.Text})
		if err != nil {
			return fmt.Errorf("email/tencent_ses: marshal template data: %w", err)
		}
		payload.Template = &struct {
			TemplateID   int64  `json:"TemplateID"`
			TemplateData string `json:"TemplateData"`
		}{TemplateID: s.cfg.TemplateID, TemplateData: string(data)}
	} else {
		payload.Simple = &struct {
			Html string `json:"Html,omitempty"`
			Text string `json:"Text,omitempty"`
		}{Html: b64(msg.HTML), Text: b64(msg.Text)}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("email/tencent_ses: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("email/tencent_ses: build request: %w", err)
	}
	now := time.Now()
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", tencentSESHost)
	req.Header.Set("X-TC-Action", "SendEmail")
	req.Header.Set("X-TC-Version", tencentSESVersion)
	req.Header.Set("X-TC-Region", s.cfg.Region)
	req.Header.Set("X-TC-Timestamp", strconv.FormatInt(now.Unix(), 10))
	req.Header.Set("Authorization", tc3Authorization(s.cfg.SecretID, s.cfg.SecretKey, tencentSESService, tencentSESHost, "sendemail", body, now))

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("email/tencent_ses: request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	// Tencent returns HTTP 200 with Response.Error on business failures.
	var out struct {
		Response struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"Response"`
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("email/tencent_ses: send failed (status %d): %s", resp.StatusCode, string(respBody))
	}
	if json.Unmarshal(respBody, &out) == nil && out.Response.Error != nil {
		return fmt.Errorf("email/tencent_ses: send failed: %s: %s", out.Response.Error.Code, out.Response.Error.Message)
	}
	return nil
}

// b64 base64-encodes non-empty content, as SendEmail.Simple requires.
func b64(s string) string {
	if s == "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// tc3Authorization builds the Tencent Cloud TC3-HMAC-SHA256 Authorization
// header for a JSON POST to "/".
func tc3Authorization(secretID, secretKey, service, host, action string, body []byte, now time.Time) string {
	date := now.UTC().Format("2006-01-02")
	canonicalHeaders := "content-type:application/json; charset=utf-8\nhost:" + host + "\nx-tc-action:" + action + "\n"
	signedHeaders := "content-type;host;x-tc-action"
	hashedPayload := sha256Hex(body)
	canonicalRequest := strings.Join([]string{
		http.MethodPost, "/", "", canonicalHeaders, signedHeaders, hashedPayload,
	}, "\n")

	credentialScope := date + "/" + service + "/tc3_request"
	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256",
		strconv.FormatInt(now.Unix(), 10),
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	secretDate := hmacSHA256([]byte("TC3"+secretKey), date)
	secretService := hmacSHA256(secretDate, service)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	return fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		secretID, credentialScope, signedHeaders, signature)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}
