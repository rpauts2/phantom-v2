package menu

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func key(s string) tea.KeyMsg {
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
	// стартуем с коннекта: Init пингует API
	nm, _ := m.Update(statusMsg{node: "n1"})
	m = nm.(model)
	if m.screen != sMenu || m.conn != "node=n1" {
		t.Fatalf("connect: screen=%d conn=%q", m.screen, m.conn)
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

func TestConnectError(t *testing.T) {
	m := initialModel(&Client{Base: "http://127.0.0.1:1", Stealth: "x"})
	nm, _ := m.Update(statusMsg{err: errString("refused")})
	m = nm.(model)
	if m.screen != sResult || !m.isErr {
		t.Fatal("conn error must show ERR screen")
	}
}

func TestModelBlockValidation(t *testing.T) {
	m := initialModel(&Client{Base: "http://127.0.0.1:1", Stealth: "x"})
	m.screen = sBlock
	ins, labels := mkInputs([]string{"ip", "why"}, nil)
	m.inputs, m.labels = ins, labels
	m.focus = 0
	nm, _ := m.Update(key("enter"))
	if !nm.(model).isErr {
		t.Fatal("empty ip must error without network")
	}
}

func TestLureFormFields(t *testing.T) {
	m := initialModel(&Client{Base: "http://127.0.0.1:1", Stealth: "x"})
	m.screen = sMenu
	// выбираем Smart lure+ (5-й пункт, индекс 4)
	down := tea.KeyMsg{Type: tea.KeyDown}
	for i := 0; i < 4; i++ {
		nm, _ := m.Update(down)
		m = nm.(model)
	}
	nm, _ := m.Update(key("enter"))
	m = nm.(model)
	if m.screen != sLure || len(m.inputs) != 6 {
		t.Fatalf("lure form: screen=%d inputs=%d", m.screen, len(m.inputs))
	}
	if m.inputs[0].Value() != "/l/op01" {
		t.Fatalf("default path: %q", m.inputs[0].Value())
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestPhishAdminForms(t *testing.T) {
	m := initialModel(&Client{Base: "http://127.0.0.1:1", Stealth: "x"})
	m.screen = sMenu
	down := tea.KeyMsg{Type: tea.KeyDown}
	for i := 0; i < 7; i++ {
		nm, _ := m.Update(down)
		m = nm.(model)
	}
	nm, _ := m.Update(key("enter"))
	m = nm.(model)
	if m.screen != sPhishDomain || len(m.inputs) != 2 {
		t.Fatalf("domain form: screen=%d inputs=%d", m.screen, len(m.inputs))
	}
	nm, _ = m.Update(key("esc"))
	m = nm.(model)
	for i := 0; i < 1; i++ {
		nm, _ := m.Update(down)
		m = nm.(model)
	}
	nm, _ = m.Update(key("enter"))
	m = nm.(model)
	if m.screen != sPhishToggle || len(m.inputs) != 2 {
		t.Fatalf("toggle form: screen=%d inputs=%d", m.screen, len(m.inputs))
	}
}

