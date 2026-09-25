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

func TestCertReuseAndAutocertOff(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "c.pem")
	key := filepath.Join(dir, "k.pem")
	m := AutoCert{CertFile: cert, KeyFile: key, DNS: dns.Disabled{}, Lab: true, Autocert: true}
	if err := m.EnsureWildcard(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	fi1, _ := os.Stat(cert)
	if err := m.EnsureWildcard(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	fi2, _ := os.Stat(cert)
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Fatal("valid cert must be reused, not reissued")
	}
	m2 := AutoCert{CertFile: filepath.Join(dir, "no.pem"), KeyFile: filepath.Join(dir, "no-key.pem"), DNS: dns.Disabled{}, Autocert: false}
	if err := m2.EnsureWildcard(context.Background(), "example.com"); err == nil {
		t.Fatal("autocert off must fail without files")
	}
	if certOK(cert, "other.com") {
		t.Fatal("wrong domain must not match")
	}
	if !certOK(cert, "example.com") {
		t.Fatal("own domain must match")
	}
}
