import sys

p = 'internal/menu/tui.go'
d = open(p, encoding='utf-8').read()
log = []

def rep(old, new):
    global d
    assert old in d, 'MISSING: ' + old[:70]
    d = d.replace(old, new, 1)

# --- isForm: + sDomainAdd, старые sPhishDomain/sPhishToggle больше не формы-ввода
rep("""func (m model) isForm() bool {
\treturn m.screen == sBlock || m.screen == sLure || m.screen == sGenerate ||
\t\tm.screen == sPhishDomain || m.screen == sPhishToggle
}""",
"""func (m model) isForm() bool {
\treturn m.screen == sBlock || m.screen == sLure || m.screen == sGenerate ||
\t\tm.screen == sDomainAdd
}

// openPick открывает пикер со списком.
func (m model) openPick(title, kind string, items []string) model {
\tli := make([]list.Item, 0, len(items))
\tfor _, t := range items {
\t\tli = append(li, pickItem{t})
\t}
\tdelegate := list.NewDefaultDelegate()
\tdelegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.
\t\tForeground(lipgloss.Color("63")).Bold(true)
\tpl := list.New(li, delegate, 56, 14)
\tpl.Title = title
\tpl.SetShowStatusBar(false)
\tpl.SetFilteringEnabled(false)
\tm.screen, m.pickTitle, m.pickList, m.pickKind = sPick, title, pl, kind
\treturn m
}

type pickItem struct{ title string }

func (i pickItem) Title() string       { return i.title }
func (i pickItem) Description() string { return "" }
func (i pickItem) FilterValue() string { return i.title }""")

# --- Update: роутинг sPick/sPhishDetail + pickList
rep("""\tvar cmd tea.Cmd
\tif m.screen == sMenu {
\t\tm.list, cmd = m.list.Update(msg)
\t\treturn m, cmd
\t}""",
"""\tvar cmd tea.Cmd
\tif m.screen == sMenu {
\t\tm.list, cmd = m.list.Update(msg)
\t\treturn m, cmd
\t}
\tif m.screen == sPick {
\t\tif km, ok := msg.(tea.KeyMsg); ok {
\t\t\tswitch km.String() {
\t\t\tcase "enter":
\t\t\t\treturn m.pickEnter()
\t\t\tcase "a":
\t\t\t\tif m.pickKind == "domains" {
\t\t\t\t\tm.inputs, m.labels = mkInputs([]string{"новый домен"}, []string{""})
\t\t\t\t\tm.focus = 0
\t\t\t\t\tm.screen = sDomainAdd
\t\t\t\t\tm.pickPhishlet = ""
\t\t\t\t\treturn m, nil
\t\t\t\t}
\t\t\tcase "x":
\t\t\t\tif m.pickKind == "domains" {
\t\t\t\t\treturn m.pickDelete()
\t\t\t\t}
\t\t\t}
\t\t}
\t\tm.pickList, cmd = m.pickList.Update(msg)
\t\treturn m, cmd
\t}
\tif m.screen == sPhishDetail {
\t\tif km, ok := msg.(tea.KeyMsg); ok {
\t\t\tswitch km.String() {
\t\t\tcase "d":
\t\t\t\treturn m.openDomainPick(m.pickPhishlet)
\t\t\tcase "t":
\t\t\t\ton := !m.pickEnabled
\t\t\t\tif err := m.client.SetPhishlet(m.pickPhishlet, nil, &on); err != nil {
\t\t\t\t\treturn m.showResult("on/off: " + err.Error(), true), nil
\t\t\t\t}
\t\t\t\tm.pickEnabled = on
\t\t\t\tstate := "выключен"
\t\t\t\tif on {
\t\t\t\t\tstate = "включен"
\t\t\t\t}
\t\t\t\treturn m.showResult(m.pickPhishlet+" "+state, false), nil
\t\t\t}
\t\t}
\t\treturn m, nil
\t}""")

open(p, 'w', encoding='utf-8', newline='').write(d)
print('part B ok')
