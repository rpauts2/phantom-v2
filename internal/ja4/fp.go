// Package ja4 — реальный JA4-подобный отпечаток из TLS ConnectionState.
// v1: version + число шифров + первый шифр + ALPN. Пусто если plain HTTP.
// Заголовок X-JA4 остается только как fallback для тестов/прокси-цепочки.
package ja4

import (
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"net/http"
	"os"
	"sort"
	"strings"
)

// AllowHeaderFallback разрешает fallback на X-JA4 ТОЛЬКО в lab.
// Prod-дефолт false: заголовок от клиента игнорируется (иначе спуфинг детекта).
// Включается env PHANTOM_TRUST_XJA4=1 (доверенный reverse-proxy перед нами).
var AllowHeaderFallback = os.Getenv("PHANTOM_TRUST_XJA4") == "1"

func Compute(cs *tls.ConnectionState) string {
	if cs == nil {
		return ""
	}
	ver := "unknown"
	switch cs.Version {
	case tls.VersionTLS10:
		ver = "tls10"
	case tls.VersionTLS11:
		ver = "tls11"
	case tls.VersionTLS12:
		ver = "tls12"
	case tls.VersionTLS13:
		ver = "tls13"
	}
	alpn := "noalpn"
	if cs.NegotiatedProtocol != "" {
		alpn = cs.NegotiatedProtocol
	}
	sni := "nosni"
	if cs.ServerName != "" {
		sni = "sni"
	}
	return fmt.Sprintf("%s-c%d-%s-%s", ver, cs.CipherSuite, alpn, sni)
}

func FromRequest(r *http.Request) string {
	if r.TLS != nil {
		if fp := Compute(r.TLS); fp != "" {
			return fp
		}
	}
	// Fallback только lab: в prod заголовок от клиента — спуфинг.
	if AllowHeaderFallback {
		return strings.TrimSpace(r.Header.Get("X-JA4"))
	}
	return ""
}

// HA — JA4H-аппроксимация: хэш присутствующих заголовков + их порядка.
// Честное ограничение: net/http теряет wire-порядок (map), поэтому это
// presence-сигнал, а не настоящий JA4H. Настоящий JA4H требует raw-сокет.
func HA(r *http.Request) string {
	names := make([]string, 0, len(r.Header))
	for k := range r.Header {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	h := fnv.New32a()
	h.Write([]byte(r.Method))
	for _, n := range names {
		h.Write([]byte("," + n))
	}
	if len(r.Cookies()) > 0 {
		h.Write([]byte(",cookies"))
	}
	return fmt.Sprintf("ja4h%d-%x", len(names), h.Sum32())
}
