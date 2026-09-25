package dns

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDisabledAndFile(t *testing.T) {
	d, err := For("disabled")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureA(context.Background(), "x.test", "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// file провайдер пишет zone локально
	f := File{Path: filepath.Join(dir, "zone.txt")}
	if err := f.EnsureA(context.Background(), "a.test", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.Path)
	if len(b) == 0 {
		t.Fatal("zone empty")
	}
	if _, err := For("route53"); err == nil {
		t.Fatal("route53 must error without creds wiring")
	}
}
