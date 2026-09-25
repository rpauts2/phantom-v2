import sys

p = 'internal/menu/tui.go'
d = open(p, encoding='utf-8').read()

def rep(old, new):
    global d
    assert old in d, 'MISSING: ' + old[:70]
    d = d.replace(old, new, 1)

helpers = '''
// phishNames возвращает "id ●/○" строки + карту enabled.
func (m model) phishNames() ([]string, map[string]bool, error) {
\tdet, err := m.client.PhishletsDetail()
\tif err != nil {
\t\treturn nil, nil, err
\t}
\titems := make([]string, 0, len(det))
\ten := map[string]bool{}
\tfor _, p := range det {
\t\tmark := "\\u25cf"
\t\tif !p.Enabled {
\t\t\tmark = "\\u25cb"
\t\t}
\t\titems = append(items, mark+" "+p.ID)
\t\ten[p.ID] = p.Enabled
\t}
\treturn items, en, nil
}

func phishID(display string) string {
\tf := strings.Fields(display)
\tif len(f) == 0 {
\t\treturn display
\t}
\treturn f[len(f)-1]
}

// openDomainPick — пикер пресетов (+ новый) для фишлета.
func (m model) openDomainPick(phishlet string) (tea.Model, tea.Cmd) {
\tdoms, err := m.client.ListDomains()
\tif err != nil {
\t\treturn m.showResult("domains: " + err.Error(), true), nil
\t}
\tm.pickPhishlet = phishlet
\titems := append([]string{"+ новый домен…"}, doms...)
\treturn m.openPick("домен для "+phishlet, "domain", items), nil
}

// pickEnter — выбор в пикере по kind.
func (m model) pickEnter() (tea.Model, tea.Cmd) {
\tsel, ok := m.pickList.SelectedItem().(pickItem)
\tif !ok {
\t\treturn m, nil
\t}
\tswitch m.pickKind {
\tcase "phish-act":
\t\tm.pickPhishlet = phishID(sel.title)
\t\tdet, err := m.client.PhishletsDetail()
\t\tif err != nil {
\t\t\treturn m.showResult("detail: " + err.Error(), true), nil
\t\t}
\t\tfor _, p := range det {
\t\t\tif p.ID == m.pickPhishlet {
\t\t\t\tm.pickEnabled = p.Enabled
\t\t\t\tm.screen = sPhishDetail
\t\t\t\treturn m, nil
\t\t\t}
\t\t}
\t\treturn m.showResult("нет такого фишлета", true), nil
\tcase "phish-domain", "phish-toggle":
\t\tid := phishID(sel.title)
\t\tif m.pickKind == "phish-toggle" {
\t\t\tdet, err := m.client.PhishletsDetail()
\t\t\tif err != nil {
\t\t\t\treturn m.showResult("detail: " + err.Error(), true), nil
\t\t\t}
\t\t\ton := true
\t\t\tfor _, p := range det {
\t\t\t\tif p.ID == id {
\t\t\t\t\ton = !p.Enabled
\t\t\t\t}
\t\t\t}
\t\t\tif err := m.client.SetPhishlet(id, nil, &on); err != nil {
\t\t\t\treturn m.showResult("on/off: " + err.Error(), true), nil
\t\t\t}
\t\t\tstate := "выключен"
\t\t\tif on {
\t\t\t\tstate = "включен"
\t\t\t}
\t\t\treturn m.showResult(id+" "+state, false), nil
\t\t}
\t\treturn m.openDomainPick(id)
\tcase "domain":
\t\tif strings.HasPrefix(sel.title, "+ ") {
\t\t\tm.inputs, m.labels = mkInputs([]string{"новый домен"}, []string{""})
\t\t\tm.focus = 0
\t\t\tm.screen = sDomainAdd
\t\t\treturn m, nil
\t\t}
\t\tif m.pickPhishlet == "" {
\t\t\treturn m.showResult("домен: " + sel.title, false), nil
\t\t}
\t\tif err := m.client.SetPhishlet(m.pickPhishlet, []string{sel.title}, nil); err != nil {
\t\t\treturn m.showResult("domain: " + err.Error(), true), nil
\t\t}
\t\treturn m.showResult(m.pickPhishlet+" → "+sel.title, false), nil
\tcase "domains":
\t\treturn m.showResult("домен: " + sel.title + "  (a-добавить x-удалить)", false), nil
\t}
\treturn m, nil
}

// pickDelete удаляет выбранный пресет и обновляет список.
func (m model) pickDelete() (tea.Model, tea.Cmd) {
\tsel, ok := m.pickList.SelectedItem().(pickItem)
\tif !ok {
\t\treturn m, nil
\t}
\tif err := m.client.RemoveDomain(sel.title); err != nil {
\t\treturn m.showResult("del: " + err.Error(), true), nil
\t}
\tdoms, err := m.client.ListDomains()
\tif err != nil {
\t\treturn m.showResult("domains: " + err.Error(), true), nil
\t}
\treturn m.openPick("пресеты доменов  (a-добавить x-удалить)", "domains", doms), nil
}
'''

anchor = 'func (m model) onEnter() (tea.Model, tea.Cmd) {'
assert anchor in d, 'onEnter missing'
d = d.replace(anchor, helpers + '\n' + anchor, 1)

open(p, 'w', encoding='utf-8', newline='').write(d)
print('part C ok')
