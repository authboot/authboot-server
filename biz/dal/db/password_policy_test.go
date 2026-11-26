package db

import "testing"

func TestPasswordPolicyCheck(t *testing.T) {
	def := DefaultPasswordPolicy()
	if !def.Check("12345678") || def.Check("1234567") {
		t.Fatal("default policy should be length-only 8+")
	}
	if def.Check(string(make([]byte, 73))) {
		t.Fatal("over 72 bytes must fail")
	}

	strict := &PasswordPolicy{MinLength: 10, RequireLowercase: true, RequireUppercase: true, RequireDigit: true, RequireSymbol: true}
	cases := map[string]bool{
		"Abcdefgh1!": true,
		"abcdefgh1!": false, // no upper
		"ABCDEFGH1!": false, // no lower
		"Abcdefghi!": false, // no digit
		"Abcdefgh12": false, // no symbol
		"Abcdefg1!":  false, // too short
		"密码Abcdef1!": true,  // non-ASCII letters are letters, not symbols
	}
	for pw, want := range cases {
		if got := strict.Check(pw); got != want {
			t.Errorf("%q: got %v want %v", pw, got, want)
		}
	}
}

func TestPasswordPolicyHintAndNormalize(t *testing.T) {
	p := &PasswordPolicy{MinLength: 3, RequireDigit: true, Hint: "  "}
	p.Normalize()
	if p.MinLength != PasswordMinLengthFloor || p.Hint != "" {
		t.Fatalf("normalize: %+v", p)
	}
	if got := p.EffectiveHint(); got != "Use at least 8 characters, including a number." {
		t.Fatalf("hint = %q", got)
	}
	p.Hint = "custom"
	if p.EffectiveHint() != "custom" {
		t.Fatal("explicit hint should win")
	}
}
