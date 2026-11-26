package email

import (
	"context"
	"strings"
	"testing"
)

func TestTemplateCatalogDefaultsCompile(t *testing.T) {
	ids := map[string]bool{}
	for _, d := range TemplateCatalog() {
		ids[d.ID] = true
		c, err := d.Compile(d.DefaultSubject, d.DefaultBody())
		if err != nil {
			t.Fatalf("%s default does not compile: %v", d.ID, err)
		}
		subject, html, err := c.Execute(d.SampleData())
		if err != nil || subject == "" || html == "" {
			t.Fatalf("%s default render: %q %q %v", d.ID, subject, html, err)
		}
	}
	for _, id := range []string{"verification_code", "invitation", "security_alert"} {
		if !ids[id] {
			t.Fatalf("missing template %s", id)
		}
	}
}

func TestCompileRejectsBadTemplates(t *testing.T) {
	d, _ := LookupTemplate("verification_code")
	cases := map[string][2]string{
		"empty subject":    {"", "<p>{{.Code}}</p>"},
		"missing required": {"s", "<p>no code here</p>"},
		"syntax error":     {"s", "<p>{{.Code</p>"},
		"unknown variable": {"s", "<p>{{.Code}} {{.Nope}}</p>"},
		"too long":         {"s", "<p>{{.Code}}</p>" + strings.Repeat("x", TemplateBodyMax)},
	}
	for name, c := range cases {
		if _, err := d.Compile(c[0], c[1]); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := d.Compile("Code {{.Code}}", "<p>{{.Code}} / {{.ExpireMinutes}}</p>"); err != nil {
		t.Fatalf("valid template rejected: %v", err)
	}
}

func TestBodyEscapesVariables(t *testing.T) {
	d, _ := LookupTemplate("invitation")
	c, err := d.Compile("Invite", "<p>{{.Token}}</p>")
	if err != nil {
		t.Fatal(err)
	}
	_, html, err := c.Execute(map[string]any{"Token": "<script>x</script>", "ExpireAt": ""})
	if err != nil || strings.Contains(html, "<script>") {
		t.Fatalf("html not escaped: %q %v", html, err)
	}
}

func TestRenderForWithoutDBUsesDefault(t *testing.T) {
	subject, html, err := RenderFor(context.Background(), 0, "verification_code", map[string]any{"Code": "123456", "ExpireMinutes": 5})
	if err != nil || subject != "你的验证码" || !strings.Contains(html, "123456") {
		t.Fatalf("%q %q %v", subject, html, err)
	}
	if _, _, err := RenderFor(context.Background(), 0, "nope", nil); err == nil {
		t.Fatal("unknown template should fail")
	}
}
