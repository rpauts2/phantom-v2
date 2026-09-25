package ja4

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestComputeFallback(t *testing.T) {
	if got := Compute(nil); got != "" {
		t.Fatal("nil must be empty")
	}
	cs := &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: 0x1301, NegotiatedProtocol: "h2", ServerName: "x.test"}
	if got := Compute(cs); got == "" {
		t.Fatal("empty fp")
	}
	// Prod-дефолт: заголовок игнорируется.
	r, _ := http.NewRequest("GET", "http://x/", nil)
	r.Header.Set("X-JA4", "spoofed")
	if FromRequest(r) != "" {
		t.Fatal("prod must ignore X-JA4")
	}
	// Lab: fallback по флагу.
	old := AllowHeaderFallback
	AllowHeaderFallback = true
	defer func() { AllowHeaderFallback = old }()
	if FromRequest(r) != "spoofed" {
		t.Fatal("lab fallback broken")
	}
	r2, _ := http.NewRequest("GET", "http://x/", nil)
	r2.TLS = &tls.ConnectionState{Version: tls.VersionTLS12, CipherSuite: 0x2f}
	if FromRequest(r2) == "" {
		t.Fatal("tls fp broken")
	}
}

func TestHA(t *testing.T) {
	a, _ := http.NewRequest("GET", "http://x/", nil)
	a.Header.Set("User-Agent", "x")
	b, _ := http.NewRequest("GET", "http://x/", nil)
	b.Header.Set("User-Agent", "x")
	b.Header.Set("Accept-Language", "en")
	if HA(a) == "" || HA(a) == HA(b) {
		t.Fatal("HA must differ on header set")
	}
}
