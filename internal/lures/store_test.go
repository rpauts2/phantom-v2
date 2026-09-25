package lures

import "testing"

// SeedFromPhishlets-паритет: автоприманки из LurePath каждого phishlet
// (покрывает ветку main.go, где luresStore.Seed вызывается для всех phishlet).
func TestSeedAndResolve(t *testing.T) {
	s := New()

	// Пустой lurePath игнорируется.
	s.Seed("labtest", "")
	if _, ok := s.Resolve("/l/nothing"); ok {
		t.Fatal("empty lurePath must not seed anything")
	}

	// Как в configs/phishlets/labtest.yaml.
	s.Seed("labtest", "/l/test01")
	id, ok := s.Resolve("/l/test01")
	if !ok || id != "labtest" {
		t.Fatalf("Resolve(/l/test01) = %q,%v; want labtest,true", id, ok)
	}

	// Неизвестный путь — miss (engine отдаст spoof).
	if _, ok := s.Resolve("/l/nope"); ok {
		t.Fatal("unknown lure must miss")
	}

	// Add перезаписывает приманку (последний выигрывает).
	s.Add("/l/test01", "other")
	if id, _ := s.Resolve("/l/test01"); id != "other" {
		t.Fatalf("re-add must overwrite, got %q", id)
	}
}
