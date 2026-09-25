// Package upstream — транспорт к апстриму (2026 stealth).
// Default: HTTP/2 (ForceAttemptHTTP2, ALPN h2) — иначе WAF палит downgrade до HTTP/1.1.
// Chrome: uTLS HelloChrome_Auto — отпечаток upstream равен Chrome жертвы.
package upstream

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

var shared *http.Transport

// Default — общий H2-транспорт (переиспользование коннектов, keepalive).
func Default() *http.Transport {
	if shared != nil {
		return shared
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
	}
	_ = http2.ConfigureTransport(tr)
	shared = tr
	return tr
}
