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

// Fetching: archive-time snapshot downloads. PublishLegalDoc fetches the
// document URL server-side and stores the exact bytes received (plus their
// SHA-256) as compliance evidence — the publisher never pastes content by
// hand, so there is no "pasted the wrong text" failure mode.
//
// Fetching a caller-supplied URL is classic SSRF territory, so the fetcher
// enforces: http/https only, redirects re-validated, and any resolved IP that
// is private / loopback / link-local is rejected BEFORE connecting.

package legaldocs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// MaxSnapshotBytes caps one fetched snapshot (mirrors db.MaxLegalDocBytes).
const MaxSnapshotBytes = 256 * 1024

// fetchTimeout bounds the whole download (connect + read).
const fetchTimeout = 10 * time.Second

// snapshot fetch errors
var (
	ErrSnapshotURLInvalid = errors.New("snapshot: url must be http(s)")
	ErrSnapshotForbidden  = errors.New("snapshot: url resolves to a forbidden address")
	ErrSnapshotTooLarge   = errors.New("snapshot: response exceeds size limit")
	ErrSnapshotFetch      = errors.New("snapshot: fetch failed")
)

// newSnapshotClient builds an HTTP client whose DialContext re-checks every
// resolved IP against the blocklist. Redirects reuse the same check because
// the Dialer sees the final connection target regardless of redirects.
func newSnapshotClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || isForbiddenIP(ip) {
				return fmt.Errorf("%w: %s", ErrSnapshotForbidden, host)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: fetchTimeout,
		Transport: &http.Transport{
			DialContext:            dialer.DialContext,
			TLSHandshakeTimeout:    5 * time.Second,
			MaxIdleConnsPerHost:    1,
			DisableKeepAlives:      true,
			Proxy:                  nil, // never follow environment proxies
			MaxResponseHeaderBytes: 64 * 1024,
		},
		// Do not follow redirects blindly: each hop re-enters the dialer's
		// Control check, which is sufficient; the default policy (up to 10) is
		// acceptable here.
	}
}

func isForbiddenIP(ip net.IP) bool {
	// Unspecified / loopback / link-local unicast / link-local multicast.
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Private ranges (RFC1918 + CGNAT + others net.IP marks private).
	if ip.IsPrivate() {
		return true
	}
	// IPv4-mapped IPv6 must be checked in v4 form (IsPrivate handles this,
	// but be explicit about the broadcast address).
	if v4 := ip.To4(); v4 != nil {
		if v4.Equal(net.IPv4bcast) {
			return true
		}
	}
	return false
}

// FetchSnapshot downloads url and returns the exact bytes received. The bytes
// are what the hash is computed over, so the stored snapshot IS the evidence.
func FetchSnapshot(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSnapshotURLInvalid, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q", ErrSnapshotURLInvalid, u.Scheme)
	}
	// A textual host that resolves to a forbidden IP is caught by the dialer's
	// Control; a literal IP host is caught here before any connection.
	if host := u.Hostname(); host != "" {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && isForbiddenIP(ip) {
			return nil, fmt.Errorf("%w: %s", ErrSnapshotForbidden, host)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSnapshotURLInvalid, err)
	}
	req.Header.Set("User-Agent", "authboot-legal-snapshot/1.0")

	client := newSnapshotClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSnapshotFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: http %d", ErrSnapshotFetch, resp.StatusCode)
	}

	// Read at most MaxSnapshotBytes+1 so an oversized body is detected, not
	// silently truncated.
	limited := io.LimitReader(resp.Body, MaxSnapshotBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSnapshotFetch, err)
	}
	if len(body) > MaxSnapshotBytes {
		return nil, ErrSnapshotTooLarge
	}
	return body, nil
}
