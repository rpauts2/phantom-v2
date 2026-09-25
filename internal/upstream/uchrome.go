// Chrome uTLS транспорт: TCP + uTLS HelloChrome_Auto + HTTP/2 поверх.
// Требования: апстрим с H2 (Google/Microsoft/Cloudflare-цели — да).
// Дефолт остается Default(); chrome выбирается конфигом upstream_tls=chrome.
package upstream

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// ChromeTransport — *http2.Transport с uTLS-хендшейком.
func ChromeTransport() *http2.Transport {
	return &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialChrome(ctx, network, addr)
		},
	}
}

func dialChrome(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		addr += ":443"
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(raw, &utls.Config{
		ServerName: host,
		MinVersion: utls.VersionTLS12,
	}, utls.HelloChrome_Auto)
	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return uconn, nil
}
