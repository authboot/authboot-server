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

package email

import (
	"fmt"
	"net"
)

// allowedSMTPPorts lists the ports a tenant-supplied SMTP host may use. The
// server dials the host itself, so tenant input is an SSRF vector; keeping the
// port set to the standard submission ports limits what can be probed.
var allowedSMTPPorts = map[int]bool{25: true, 465: true, 587: true, 2525: true}

// checkSMTPTarget rejects tenant SMTP hosts that resolve to loopback, private,
// link-local or otherwise non-public addresses, and non-standard ports.
func checkSMTPTarget(host string, port int) error {
	if host == "" {
		return fmt.Errorf("email/smtp: host is required")
	}
	if !allowedSMTPPorts[port] {
		return fmt.Errorf("email/smtp: port %d is not allowed (use 25, 465, 587 or 2525)", port)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("email/smtp: resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("email/smtp: %q did not resolve to any address", host)
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return fmt.Errorf("email/smtp: host %q resolves to a non-public address", host)
		}
	}
	return nil
}

func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	// Carrier-grade NAT (100.64.0.0/10) and IPv4-mapped metadata endpoints are
	// not covered by IsPrivate.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return false
	}
	return true
}
