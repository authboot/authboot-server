package utils

import "strings"

// MaskContact hides the middle of an email local-part or phone number so logs
// and dashboard lists don't expose a full contact, while keeping enough to
// identify the account: al***@x.com, 138****1234. Non-contact values (usernames,
// openids) are masked from the 4th character onwards.
func MaskContact(value string) string {
	if value == "" {
		return ""
	}
	if i := strings.Index(value, "@"); i > 0 {
		local, domain := value[:i], value[i:]
		if len(local) <= 2 {
			return strings.Repeat("*", len(local)) + domain
		}
		return local[:2] + strings.Repeat("*", len(local)-2) + domain
	}
	r := []rune(value)
	n := len(r)
	if n <= 4 {
		return strings.Repeat("*", n)
	}
	return string(r[:3]) + strings.Repeat("*", n-3)
}
