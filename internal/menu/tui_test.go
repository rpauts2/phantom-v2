package menu

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func key(s string) tea.KeyMsg {
	// bubbletea KeyMsg из строки: rune-сообщение
	var r []rune
	for _, c := range s {
		r = append(r, c)
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: r, Alt: false}
}

func TestModelNav(t *testing.T) {
	srv := fakeAPI()
	defer srv.Close()
	m := initialModel(&Client{Base: srv.URL, Stealth: "s3cr3t"})
	if m.screen != sMenu {
		t.Fatal("must start at menu")
	}
	// esc в меню — остаемся
	nm, _ := m.Update(key("esc"))
	m = nm.(model)
	if m.screen != sMenu {
		t.Fatal("esc in menu")
	}
	// enter на первом пункте (Dashboard) — результат без ошибки
	nm, _ = m.Update(key("enter"))
	m = nm.(model)
	if m.screen != sResult || m.isErr {
		t.Fatalf("dashboard: screen=%d err=%v %s", m.screen, m.isErr, m.result)
	}
	// esc — назад в меню
	nm, _ = m.Update(key("esc"))
	if nm.(model).screen != sMenu {
		t.Fatal("esc must return to menu")
	}
}

func TestModelBlockValidation(t *testing.T) {
	m := initialModel(&Client{Base: "http://127.0.0.1:1", Stealth: "x"})
	m.screen = sBlock
	m.inputs = mkInputs([]string{"ip", "why"})
	m.focus = 0
	nm, _ := m.Update(key("enter"))
	if !nm.(model).isErr {
		t.Fatal("empty ip must error without network")
	}
}
