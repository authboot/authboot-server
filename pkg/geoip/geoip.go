// Package geoip resolves approximate login locations exclusively from local data.
package geoip

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/lionsoul2014/ip2region/binding/golang/service"
	"github.com/oschwald/geoip2-golang"
)

type Location struct {
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	Region      string `json:"region"`
	City        string `json:"city"`
	Display     string `json:"display"`
	Source      string `json:"source"`
	Status      string `json:"status"`
}

type lookup func(netip.Addr) (Location, error)
type Resolver struct{ domestic, global lookup }

func Unknown(status string) Location {
	return Location{Display: "未知地区", Source: "unknown", Status: status}
}

var excluded = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, p := range excluded {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func (r *Resolver) Resolve(raw string) Location {
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return Unknown("invalid_ip")
	}
	ip = ip.Unmap()
	if !Public(ip) {
		return Unknown("non_public")
	}
	var a, b Location
	var ea, eb error
	if r.domestic != nil && ip.Is4() {
		a, ea = r.domestic(ip)
	}
	if a.CountryCode == "CN" && ea == nil {
		return finish(a, "ip2region")
	}
	if r.global != nil {
		b, eb = r.global(ip)
	}
	if eb == nil && b.Country != "" {
		return finish(b, "geolite2")
	}
	if ea == nil && a.Country != "" {
		return finish(a, "ip2region")
	}
	if ea != nil || eb != nil {
		return Unknown("lookup_error")
	}
	if r.domestic == nil && r.global == nil {
		return Unknown("unavailable")
	}
	return Unknown("not_found")
}

func finish(l Location, source string) Location {
	l.Source, l.Status = source, "approximate"
	parts := []string{}
	for _, s := range []string{l.Country, l.Region, l.City} {
		if s != "" && (len(parts) == 0 || parts[len(parts)-1] != s) {
			parts = append(parts, s)
		}
	}
	l.Display = strings.Join(parts, " · ") + "（IP 近似位置）"
	return l
}

func parseRegion(s string) Location {
	p := strings.Split(s, "|")
	if len(p) != 5 {
		return Location{}
	}
	for i := range p {
		if p[i] == "0" || p[i] == "-" {
			p[i] = ""
		}
	}
	code := strings.ToUpper(p[4])
	if code != "" && (len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z') {
		return Location{}
	}
	return Location{Country: p[0], Region: p[1], City: p[2], CountryCode: code}
}

// Open loads both databases once. A broken/missing database disables only that source.
// Close must be called after requests have drained.
func Open(xdbPath, cityPath string) (*Resolver, func(), []error) {
	r := &Resolver{}
	var issues []error
	var city *geoip2.Reader
	var regions *service.Ip2Region
	if xdbPath == "" {
		issues = append(issues, fmt.Errorf("IP2REGION_DB_PATH is unset"))
	} else {
		cfg, err := service.NewV4Config(service.BufferCache, xdbPath, 1)
		if err == nil {
			regions, err = service.NewIp2Region(cfg, nil)
		}
		if err != nil {
			issues = append(issues, fmt.Errorf("ip2region: %w", err))
		} else {
			// This SDK revision writes a shared counter even in BufferCache mode.
			var mu sync.Mutex
			r.domestic = func(ip netip.Addr) (loc Location, err error) {
				mu.Lock()
				defer mu.Unlock()
				// The upstream reader can panic on corrupt offsets.
				defer func() {
					if recover() != nil {
						err = fmt.Errorf("corrupt xdb data")
					}
				}()
				s, err := regions.Search(ip.String())
				return parseRegion(s), err
			}
		}
	}
	if cityPath == "" {
		issues = append(issues, fmt.Errorf("GEOLITE2_CITY_DB_PATH is unset"))
	} else {
		var err error
		city, err = geoip2.Open(cityPath)
		if err == nil && !strings.Contains(city.Metadata().DatabaseType, "City") {
			_ = city.Close()
			city = nil
			err = fmt.Errorf("expected City database")
		}
		if err != nil {
			issues = append(issues, fmt.Errorf("geolite2: %w", err))
		} else {
			r.global = func(ip netip.Addr) (Location, error) {
				c, err := city.City(net.IP(ip.AsSlice()))
				if err != nil {
					return Location{}, err
				}
				l := Location{CountryCode: c.Country.IsoCode, Country: name(c.Country.Names), City: name(c.City.Names)}
				if len(c.Subdivisions) > 0 {
					l.Region = name(c.Subdivisions[0].Names)
				}
				return l, nil
			}
		}
	}
	return r, func() {
		if regions != nil {
			regions.Close()
		}
		if city != nil {
			_ = city.Close()
		}
	}, issues
}

func name(names map[string]string) string {
	if s := names["zh-CN"]; s != "" {
		return s
	}
	return names["en"]
}

var once sync.Once
var defaultResolver *Resolver
var closeDefault func()

func Init() {
	once.Do(func() {
		var issues []error
		defaultResolver, closeDefault, issues = Open(os.Getenv("IP2REGION_DB_PATH"), os.Getenv("GEOLITE2_CITY_DB_PATH"))
		if len(issues) > 0 {
			log.Printf("login GeoIP degraded: %v", issues)
		}
	})
}
func Resolve(ip string) Location { Init(); return defaultResolver.Resolve(ip) }
func Close() {
	if closeDefault != nil {
		closeDefault()
	}
}
