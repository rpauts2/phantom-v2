package menu

import (
	"strings"
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
	srv := fakeAPI()
	defer srv.Close()
	c := &Client{Base: srv.URL, Stealth: "s3cr3t"}
	down := tea.KeyMsg{Type: tea.KeyDown}
	enter := key("enter")

	// Phishlet domain: меню idx7 -> пикер фишлетов
	m := initialModel(c)
	m.screen = sMenu
	for i := 0; i < 7; i++ {
		nm, _ := m.Update(down)
		m = nm.(model)
	}
	nm, _ := m.Update(enter)
	m = nm.(model)
	if m.screen != sPick || m.pickKind != "phish-domain" {
		t.Fatalf("phish picker: screen=%d kind=%s", m.screen, m.pickKind)
	}
	// enter на "a" -> пикер доменов (пресет evil.test + новый)
	nm, _ = m.Update(enter)
	m = nm.(model)
	if m.screen != sPick || m.pickKind != "domain" {
		t.Fatalf("domain picker: screen=%d kind=%s", m.screen, m.pickKind)
	}
	if m.pickPhishlet != "a" {
		t.Fatalf("phishlet ctx: %q", m.pickPhishlet)
	}
	// курсор на "+ новый домен…" (первый) -> форма
	nm, _ = m.Update(enter)
	m = nm.(model)
	if m.screen != sDomainAdd || len(m.inputs) != 1 {
		t.Fatalf("domain add: screen=%d inputs=%d", m.screen, len(m.inputs))
	}
	m.inputs[0].SetValue("n.test")
	nm, _ = m.Update(enter)
	m = nm.(model)
	if m.screen != sResult || m.isErr {
		t.Fatalf("apply: screen=%d err=%v %s", m.screen, m.isErr, m.result)
	}

	// Phishlet on/off: idx8 -> пикер -> enter сразу тоглит
	m2 := initialModel(c)
	m2.screen = sMenu
	for i := 0; i < 8; i++ {
		nm, _ := m2.Update(down)
		m2 = nm.(model)
	}
	nm, _ = m2.Update(enter)
	m2 = nm.(model)
	if m2.screen != sPick || m2.pickKind != "phish-toggle" {
		t.Fatalf("toggle picker: screen=%d kind=%s", m2.screen, m2.pickKind)
	}
	nm, _ = m2.Update(enter)
	m2 = nm.(model)
	if m2.screen != sResult || m2.isErr {
		t.Fatalf("toggle: screen=%d err=%v %s", m2.screen, m2.isErr, m2.result)
	}

// Domains: idx11 -> пресеты; x удаляет
	m3 := initialModel(c)
	m3.screen = sMenu
	for i := 0; i < 11; i++ {
		nm, _ := m3.Update(down)
		m3 = nm.(model)
	}
	nm, _ = m3.Update(enter)
	m3 = nm.(model)
	if m3.screen != sPick || m3.pickKind != "domains" {
		t.Fatalf("domains pick: screen=%d kind=%s", m3.screen, m3.pickKind)
	}
	nm, _ = m3.Update(key("x"))
	m3 = nm.(model)
	if m3.screen != sPick {
		t.Fatalf("after del: screen=%d %s", m3.screen, m3.result)
	}
}
func TestCampFlow(t *testing.T) {
	srv := fakeAPI()
	defer srv.Close()
	c := &Client{Base: srv.URL, Stealth: "s3cr3t"}
	down := tea.KeyMsg{Type: tea.KeyDown}
	enter := key("enter")
	// Campaigns idx9 -> пикер
	m := initialModel(c)
	m.screen = sMenu
	for i := 0; i < 9; i++ {
		nm, _ := m.Update(down)
		m = nm.(model)
	}
	nm, _ := m.Update(enter)
	m = nm.(model)
	if m.screen != sPick {
		t.Fatalf("camps pick: screen=%d", m.screen)
	}
	// enter на c1 -> stats
	nm, _ = m.Update(enter)
	m = nm.(model)
	if m.screen != sResult || m.isErr {
		t.Fatalf("camp stats: screen=%d err=%v %s", m.screen, m.isErr, m.result)
	}
	// Campaign+ idx10 -> форма 7 полей
	m2 := initialModel(c)
	m2.screen = sMenu
	for i := 0; i < 10; i++ {
		nm, _ := m2.Update(down)
		m2 = nm.(model)
	}
	nm, _ = m2.Update(enter)
	m2 = nm.(model)
	if m2.screen != sCampNew || len(m2.inputs) != 7 {
		t.Fatalf("camp form: screen=%d inputs=%d", m2.screen, len(m2.inputs))
	}
}
func TestCapturesScreen(t *testing.T) {
	srv := fakeAPI()
	defer srv.Close()
	_ = srv
	c := &Client{Base: srv.URL, Stealth: "s3cr3t"}
	m := initialModel(c)
	m.screen = sMenu
	down := tea.KeyMsg{Type: tea.KeyDown}
	for i := 0; i < 12; i++ {
		nm, _ := m.Update(down)
		m = nm.(model)
	}
	nm, _ := m.Update(key("enter"))
	m = nm.(model)
	if m.screen != sResult || m.isErr {
		t.Fatalf("captures: screen=%d err=%v %s", m.screen, m.isErr, m.result)
	}
	if m.result == "" {
		t.Fatal("empty captures")
	}
}

func TestDigitsAndCrumb(t *testing.T) {
	srv := fakeAPI()
	defer srv.Close()
	c := &Client{Base: srv.URL, Stealth: "s3cr3t"}
	m := initialModel(c)
	m.screen = sMenu
	if m.where() != "\u043c\u0435\u043d\u044e" {
		t.Fatalf("crumb: %q", m.where())
	}
	// цифра 3 -> Phishlets (idx2) -> пикер
	nm, _ := m.Update(key("3"))
	m = nm.(model)
	if m.screen != sPick || m.where() == "menu" {
		t.Fatalf("digit: screen=%d crumb=%q", m.screen, m.where())
	}
	// r в пикере — перезагрузка списка
	nm, _ = m.Update(key("r"))
	m = nm.(model)
	if m.screen != sPick {
		t.Fatalf("refresh: screen=%d", m.screen)
	}
	// крошка пикера содержит заголовок
	if m.where() == "" {
		t.Fatal("empty crumb")
	}
}

func TestReloadPickKinds(t *testing.T) {
	srv := fakeAPI()
	defer srv.Close()
	c := &Client{Base: srv.URL, Stealth: "s3cr3t"}
	m := initialModel(c)
	m.screen = sMenu
	// Campaigns idx9 -> пикер camp
	down := tea.KeyMsg{Type: tea.KeyDown}
	for i := 0; i < 9; i++ {
		nm, _ := m.Update(down)
		m = nm.(model)
	}
	nm, _ := m.Update(key("enter"))
	m = nm.(model)
	if m.pickKind != "camp" {
		t.Fatalf("kind: %s", m.pickKind)
	}
	nm, _ = m.Update(key("r"))
	m = nm.(model)
	if m.screen != sPick || m.pickKind != "camp" {
		t.Fatalf("camp refresh: screen=%d kind=%s", m.screen, m.pickKind)
	}
}

func TestServerScreen(t *testing.T) {
	m := initialModel(&Client{Base: "http://127.0.0.1:1", Stealth: "x"})
	m.screen = sServer
	m.result = "сервер: down"
	nm, _ := m.Update(key("l"))
	m = nm.(model)
	if m.screen != sResult {
		t.Fatalf("logs: screen=%d", m.screen)
	}
}

func TestQuickFlow(t *testing.T) {
	srv := fakeAPI()
	defer srv.Close()
	c := &Client{Base: srv.URL, Stealth: "s3cr3t"}
	down := tea.KeyMsg{Type: tea.KeyDown}
	enter := key("enter")
	m := initialModel(c)
	m.screen = sMenu
	for i := 0; i < 14; i++ {
		nm, _ := m.Update(down)
		m = nm.(model)
	}
	nm, _ := m.Update(enter)
	m = nm.(model)
	if m.screen != sPick {
		t.Fatalf("quick pick: screen=%d", m.screen)
	}
	nm, _ = m.Update(enter)
	m = nm.(model)
	if m.screen != sResult || m.isErr {
		t.Fatalf("quick create: screen=%d err=%v %s", m.screen, m.isErr, m.result)
	}
	if !strings.Contains(m.result, "https://") {
		t.Fatalf("no url: %s", m.result)
	}
}
