import sys

p = 'internal/menu/tui.go'
d = open(p, encoding='utf-8').read()

def rep(old, new):
    global d
    assert old in d, 'MISSING: ' + old[:70]
    d = d.replace(old, new, 1)

# 1. screens
rep("\tsPhishDomain\n\tsPhishToggle\n\tsResult\n)",
    "\tsPhishDomain\n\tsPhishToggle\n\tsPick\n\tsPhishDetail\n\tsDomainAdd\n\tsResult\n)")

# 2. model fields
rep("""type model struct {
\tclient *Client
\tscreen screen
\tconn   string""",
    """type model struct {
\tclient *Client
\tscreen screen
\tconn   string
\tpickTitle string
\tpickList list.Model
\tpickKind string
\tpickPhishlet string
\tpickEnabled bool""")

# 3. Domains item before Quit
rep('\t\titem{"Quit", ',
    '\t\titem{"Domains", "пресеты доменов", sDomains},\n'
    '\t\titem{"Quit", ')

open(p, 'w', encoding='utf-8', newline='').write(d)
print('part A ok')
