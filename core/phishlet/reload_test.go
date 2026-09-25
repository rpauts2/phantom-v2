package phishlet

import (
	"os"
	"path/filepath"
	"testing"
)

const goodYAML = `id: hot1
version: 2
base_domains: ["a.test"]
proxy_hosts: [{phish_sub: "login", orig_sub: "o", domain: "u.test", is_landing: true}]
lure_path: "/l/hot1"
enabled: true
`

func TestReloadAtomic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(goodYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	st := NewStore()
	if err := st.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	// Ломаный файл: Reload обязан провалиться БЕЗ потери живого состояния.
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte("id: [broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.Reload(dir); err == nil {
		t.Fatal("broken reload must fail")
	}
	if st.FindByID("hot1") == nil {
		t.Fatal("live state clobbered")
	}
	if err := os.Remove(filepath.Join(dir, "b.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := st.Reload(dir); err != nil {
		t.Fatal(err)
	}
}

func TestUpsertReplace(t *testing.T) {
	st := NewStore()
	if _, err := st.UpsertYAML([]byte(goodYAML)); err != nil {
		t.Fatal(err)
	}
	if ph, _ := st.FindByHost("login.a.test"); ph == nil {
		t.Fatal("not resolved")
	}
	// Замена того же ID на другой sub: старый ключ исчезает.
	v2 := `id: hot1
version: 2
base_domains: ["a.test"]
proxy_hosts: [{phish_sub: "auth", orig_sub: "o", domain: "u.test", is_landing: true}]
lure_path: "/l/hot1"
enabled: true
`
	if _, err := st.UpsertYAML([]byte(v2)); err != nil {
		t.Fatal(err)
	}
	if ph, _ := st.FindByHost("login.a.test"); ph != nil {
		t.Fatal("stale host survived")
	}
	if ph, _ := st.FindByHost("auth.a.test"); ph == nil {
		t.Fatal("new host missing")
	}
	// Чужой ID на занятый хост — отказ без мутации.
	other := `id: hot2
version: 2
base_domains: ["a.test"]
proxy_hosts: [{phish_sub: "auth", orig_sub: "o", domain: "u.test", is_landing: true}]
lure_path: "/l/hot2"
enabled: true
`
	if _, err := st.UpsertYAML([]byte(other)); err == nil {
		t.Fatal("conflict must fail")
	}
	if ph, _ := st.FindByHost("auth.a.test"); ph == nil || ph.ID != "hot1" {
		t.Fatal("live state clobbered by failed upsert")
	}
}
