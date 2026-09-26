package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWizard(t *testing.T) {
	in := strings.NewReader("verdebudget.ru\nrpauts2@gmail.com\nprod\n12345\nmail.x.com\n")
	var out strings.Builder
	a := Ask(in, &out)
	if a.Domain != "verdebudget.ru" || a.Email != "rpauts2@gmail.com" || a.Mode != "prod" {
		t.Fatalf("%+v", a)
	}
	if a.TelegramChat != "12345" || a.SMTPHost != "mail.x.com" {
		t.Fatalf("%+v", a)
	}
	yml := Render(a)
	for _, want := range []string{"verdebudget.ru", "rpauts2@gmail.com", "shared_443: true", "12345"} {
		if !strings.Contains(yml, want) {
			t.Fatalf("missing %q in:\n%s", want, yml)
		}
	}
	// дефолты на пустом вводе
	a2 := Ask(strings.NewReader("\n\n\n\n\n"), &out)
	if a2.Domain != "phish.test" || a2.Mode != "lab" {
		t.Fatalf("%+v", a2)
	}
	if strings.Contains(Render(a2), "telegram_enabled: true") {
		t.Fatal("telegram must be off by default")
	}
}

func TestWriteFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := WriteFile(p, "x", strings.NewReader(""), &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "x" {
		t.Fatal("not written")
	}
	// существующий без y — отмена
	if err := WriteFile(p, "y", strings.NewReader("n\n"), &strings.Builder{}); err == nil {
		t.Fatal("must cancel")
	}
	if err := WriteFile(p, "y", strings.NewReader("y\n"), &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
}
