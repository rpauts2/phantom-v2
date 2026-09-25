// Package obfuscate — полиморфная обертка JS (Pro JS-obfuscation паритет, v1).
// v1: каждый рендер уникален (рандом-префикс/коммент), семантика src сохранена.
// Полный AST-обфускатор — следующим этапом, интерфейс уже заморожен.
package obfuscate

import (
	"fmt"
	"math/rand"
	"strings"
)

func Obfuscate(src string, seed int64) string {
	r := rand.New(rand.NewSource(seed))
	prefix := fmt.Sprintf("_p%x", r.Intn(1<<30))
	comment := fmt.Sprintf("/*%x*/", r.Intn(1<<30))
	var b strings.Builder
	b.WriteString(comment)
	fmt.Fprintf(&b, `(()=>{var %s=1;`, prefix)
	b.WriteString(src)
	b.WriteString(`})();`)
	return b.String()
}
