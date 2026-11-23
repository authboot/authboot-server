package clientip

import "testing"

func TestProxyBoundary(t *testing.T) {
	r, err := New("10.20.0.0/24,2001:db8:1::/48")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ peer, xff, real, want string }{
		{"8.8.8.8:123", "1.1.1.1", "9.9.9.9", "8.8.8.8"},
		{"10.20.0.2:123", "1.1.1.1, 10.20.0.1", "", "1.1.1.1"},
		{"10.20.0.2:123", "6.6.6.6, 8.8.8.8, 10.20.0.1", "", "8.8.8.8"},
		{"10.20.0.2:123", "", "1.1.1.1", "1.1.1.1"},
		{"10.20.0.2:123", "bad", "1.1.1.1", "10.20.0.2"},
		{"10.20.0.2:123", "1.1.1.1,", "", "10.20.0.2"},
		{"[2001:db8:1::1]:443", "2606:4700:4700::1111", "", "2606:4700:4700::1111"},
		{"[::ffff:8.8.8.8]:123", "1.1.1.1", "", "8.8.8.8"},
		{"invalid", "1.1.1.1", "", ""},
	} {
		if got := r.Resolve(tt.peer, tt.xff, tt.real); got != tt.want {
			t.Errorf("%+v got %s", tt, got)
		}
	}
	peerOnly, _ := New("")
	if got := peerOnly.Resolve("10.20.0.2:123", "1.1.1.1", ""); got != "10.20.0.2" {
		t.Fatal(got)
	}
	r, err = New("10.20.0.0/24,bad")
	if err == nil || r.Resolve("10.20.0.2:123", "1.1.1.1", "") != "10.20.0.2" {
		t.Fatal("must fail closed")
	}
}
