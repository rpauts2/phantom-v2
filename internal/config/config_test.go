package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func valid() string {
	return `bind: "0.0.0.0"
https_port: 443
domains: ["login.example.com"]
storage: {sqlite_path: "./data/phantom.db", redis_addr: "127.0.0.1:6379", session_ttl_min: 60}
tls: {email: "ops@example.com", dns_provider: "disabled", wildcard: false}
api: {stealth_hostname: "api-internal.example.com", ca_file: "./certs/ca.pem", cert_file: "./certs/server.pem", key_file: "./certs/server-key.pem"}
log_level: "info"
`
}

func TestLoadValid(t *testing.T) {
	c, err := Load(writeTemp(t, valid()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Domains) != 1 || c.Storage.SessionTTLMin != 60 {
		t.Fatalf("unexpected config: %+v", c)
	}
}

func TestRejectHardcodedAndBadDNS(t *testing.T) {
	bad := valid()
	bad += ""
	// hardcoded lab domain must fail
	p := writeTemp(t, `bind: "0.0.0.0"
https_port: 443
domains: ["verdebudget.ru"]
storage: {sqlite_path: "./data/phantom.db", redis_addr: "127.0.0.1:6379", session_ttl_min: 60}
tls: {email: "ops@example.com", dns_provider: "disabled", wildcard: false}
api: {stealth_hostname: "x.example.com", ca_file: "a", cert_file: "b", key_file: "c"}
log_level: "info"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected hardcoded domain rejection")
	}
	// wildcard without dns provider must fail
	p2 := writeTemp(t, `bind: "0.0.0.0"
https_port: 443
domains: ["login.example.com"]
storage: {sqlite_path: "./data/phantom.db", redis_addr: "127.0.0.1:6379", session_ttl_min: 60}
tls: {email: "ops@example.com", dns_provider: "disabled", wildcard: true}
api: {stealth_hostname: "x.example.com", ca_file: "a", cert_file: "b", key_file: "c"}
log_level: "info"
`)
	if _, err := Load(p2); err == nil {
		t.Fatal("expected wildcard-without-dns rejection")
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("PHANTOM_REDIS_ADDR", "10.0.0.5:6379")
	t.Setenv("PHANTOM_LOG_LEVEL", "debug")
	c, err := Load(writeTemp(t, valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage.RedisAddr != "10.0.0.5:6379" || c.LogLevel != "debug" {
		t.Fatalf("env override failed: %+v", c)
	}
}
