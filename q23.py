import sys

p = 'internal/menu/tui.go'
d = open(p, encoding='utf-8').read()

def rep(old, new):
    global d
    assert old in d, 'MISSING: ' + old[:60]
    d = d.replace(old, new, 1)

# screens
rep("\tsPick\n\tsPhishDetail\n\tsDomainAdd\n\tsResult\n)",
    "\tsPick\n\tsPhishDetail\n\tsDomainAdd\n\tsCampNew\n\tsResult\n)")

# menu items: Campaigns + Campaign+
rep('\t\titem{"Domains", ',
    '\t\titem{"Campaigns", "рассылки: статистика", sCamps},\n'
    '\t\titem{"Campaign+", "новая: цели -> launch -> send", sCampNew},\n'
    '\t\titem{"Domains", ')

# screens const sCamps
rep("\tsPick\n\tsPhishDetail\n\tsDomainAdd\n\tsCampNew\n\tsResult\n)",
    "\tsPick\n\tsPhishDetail\n\tsDomainAdd\n\tsCampNew\n\tsCamps\n\tsResult\n)")

open(p, 'w', encoding='utf-8', newline='').write(d)
print('screens ok')
