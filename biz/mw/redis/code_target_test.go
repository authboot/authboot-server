package redis

import "testing"

func TestCodeTargetNormalization(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{" User@Example.COM ", "user@example.com"},
		{" +8613800000000 ", "+8613800000000"},
		{"   ", ""},
	} {
		if got := NormalizeCodeTarget(tc.input); got != tc.want {
			t.Errorf("NormalizeCodeTarget(%q) = %q, want %q", tc.input, got, tc.want)
		}
		if codeKey("login", tc.input) != codeKey("login", tc.want) {
			t.Errorf("contact variants must share a code key: %q", tc.input)
		}
	}
	if codeKey("captcha_grant", "AbC") == codeKey("captcha_grant", "abc") {
		t.Fatal("captcha tokens must remain case-sensitive")
	}
}
