package tls

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/phantom-v2/phantom/internal/dns"
)

func TestLabWildcard(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "c.pem")
	key := filepath.Join(dir, "k.pem")
	m := AutoCert{CertFile: cert, KeyFile: key, DNS: dns.Disabled{}, Lab: true}
	if err := m.EnsureWildcard(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cert); err != nil {
		t.Fatal("cert not written")
	}
	// второй вызов — файлы уже есть
	if err := m.EnsureWildcard(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
}
