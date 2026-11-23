package geoip

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

// Synthetic fixture exercises the real upstream reader without licensed data.
func TestActualXDBReader(t *testing.T) {
	region := "中国|测试省|测试市|测试运营商|CN"
	start := xdb.XdbBufferMinBytes
	buf := make([]byte, start+14+len(region))
	binary.LittleEndian.PutUint16(buf, 2)
	binary.LittleEndian.PutUint16(buf[2:], 1)
	binary.LittleEndian.PutUint32(buf[8:], uint32(start))
	binary.LittleEndian.PutUint32(buf[12:], uint32(start))
	vector := xdb.HeaderInfoLength + (1*256+2)*8
	binary.LittleEndian.PutUint32(buf[vector:], uint32(start))
	binary.LittleEndian.PutUint32(buf[vector+4:], uint32(start))
	binary.LittleEndian.PutUint32(buf[start:], 0x01020000)
	binary.LittleEndian.PutUint32(buf[start+4:], 0x0102ffff)
	binary.LittleEndian.PutUint16(buf[start+8:], uint16(len(region)))
	binary.LittleEndian.PutUint32(buf[start+10:], uint32(start+14))
	copy(buf[start+14:], region)
	path := filepath.Join(t.TempDir(), "test.xdb")
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatal(err)
	}
	r, close, errs := Open(path, "")
	defer close()
	if len(errs) != 1 {
		t.Fatal(errs)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				l := r.Resolve("1.2.3.4")
				if l.City != "测试市" || l.Source != "ip2region" {
					t.Errorf("%+v", l)
				}
			}
		}()
	}
	wg.Wait()
}

func TestStrategy(t *testing.T) {
	cn := Location{CountryCode: "CN", Country: "中国", Region: "广东省", City: "深圳市"}
	us := Location{CountryCode: "US", Country: "美国", Region: "加利福尼亚州"}
	for _, tt := range []struct {
		name, ip string
		a, b     Location
		ae, be   error
		want     Location
		source   string
	}{
		{"china priority no mixing", "1.2.3.4", cn, us, nil, nil, cn, "ip2region"},
		{"overseas priority", "8.8.8.8", Location{Country: "美国", City: "other"}, us, nil, nil, us, "geolite2"},
		{"city reader error fallback", "8.8.8.8", us, Location{}, nil, errors.New("bad"), us, "ip2region"},
		{"xdb error fallback", "1.2.3.4", Location{}, cn, errors.New("bad"), nil, cn, "geolite2"},
		{"missing city fallback", "8.8.8.8", us, Location{}, nil, nil, us, "ip2region"},
		{"ipv6", "2606:4700:4700::1111", cn, us, nil, nil, us, "geolite2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := Resolver{domestic: func(netip.Addr) (Location, error) { return tt.a, tt.ae }, global: func(netip.Addr) (Location, error) { return tt.b, tt.be }}
			got := r.Resolve(tt.ip)
			if got != finish(tt.want, tt.source) {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestNonPublicNeverQueries(t *testing.T) {
	fail := func(netip.Addr) (Location, error) { t.Fatal("queried non-public address"); return Location{}, nil }
	r := Resolver{fail, fail}
	for _, ip := range []string{"bad", "", "127.0.0.1", "::1", "10.1.1.1", "::ffff:192.168.1.1", "fc00::1", "fe80::1", "100.64.0.1", "192.0.2.1", "198.18.0.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "2001:db8::1", "2002::1", "3fff::1", "0.1.2.3"} {
		if l := r.Resolve(ip); l.Source != "unknown" {
			t.Errorf("%s: %+v", ip, l)
		}
	}
	if l := (&Resolver{}).Resolve("8.8.8.8"); l.Status != "unavailable" {
		t.Fatal(l)
	}
}

func TestParseRegion(t *testing.T) {
	l := parseRegion("中国|广东省|深圳市|电信|CN")
	if l.CountryCode != "CN" || l.Region != "广东省" || l.City != "深圳市" {
		t.Fatal(l)
	}
	if l := parseRegion("United States|0|-|ISP|US"); l.Region != "" || l.City != "" || l.CountryCode != "US" {
		t.Fatal(l)
	}
	if l := parseRegion("garbage"); l.Country != "" {
		t.Fatal(l)
	}
}

func TestOpenMissingAndCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][2]string{{"", ""}, {path, path}, {path + "missing", path + "missing"}} {
		r, close, errs := Open(paths[0], paths[1])
		if len(errs) != 2 {
			t.Fatalf("%v", errs)
		}
		if r.Resolve("8.8.8.8").Status != "unavailable" {
			t.Fatal("expected unavailable")
		}
		close()
	}
}

func TestConcurrentResolve(t *testing.T) {
	r := Resolver{global: func(netip.Addr) (Location, error) { return Location{Country: "美国"}, nil }}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if r.Resolve("8.8.8.8").Source != "geolite2" {
					t.Error("source")
				}
			}
		}()
	}
	wg.Wait()
}
