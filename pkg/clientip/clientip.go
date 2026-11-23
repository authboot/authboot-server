package clientip

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/cloudwego/hertz/pkg/app"
)

type Resolver struct{ trusted []netip.Prefix }

func New(cidrs string) (*Resolver, error) {
	r := &Resolver{}
	for _, s := range strings.Split(cidrs, ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return &Resolver{}, fmt.Errorf("invalid trusted proxy CIDR: %w", err)
		}
		r.trusted = append(r.trusted, p)
	}
	return r, nil
}
func (r *Resolver) trusts(ip netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
func parse(s string) netip.Addr {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}
	}
	return a.Unmap()
}
func (r *Resolver) Resolve(peer, xff, real string) string {
	host, _, err := net.SplitHostPort(peer)
	if err == nil {
		peer = host
	}
	ip := parse(peer)
	if !ip.IsValid() {
		return ""
	}
	original := ip.String()
	if !r.trusts(ip) {
		return original
	}
	if strings.TrimSpace(xff) != "" {
		hops := strings.Split(xff, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			if !r.trusts(ip) {
				return ip.String()
			}
			ip = parse(hops[i])
			// Malformed XFF fails closed to peer, never to another header.
			if !ip.IsValid() {
				return original
			}
		}
		return ip.String()
	}
	if ip = parse(real); ip.IsValid() {
		return ip.String()
	}
	return original
}

var once sync.Once
var defaultResolver *Resolver

func Init() {
	once.Do(func() {
		var err error
		defaultResolver, err = New(os.Getenv("LOGIN_TRUSTED_PROXY_CIDRS"))
		if err != nil {
			log.Printf("login proxy configuration invalid; using peer only: %v", err)
		}
	})
}
func FromContext(c *app.RequestContext) string {
	Init()
	if c == nil || c.RemoteAddr() == nil {
		return ""
	}
	return defaultResolver.Resolve(c.RemoteAddr().String(), string(c.GetHeader("X-Forwarded-For")), string(c.GetHeader("X-Real-IP")))
}
