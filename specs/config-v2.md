# Config v2 (frozen)

Один файл + env-override `PHANTOM_*`. Секреты НИКОГДА в git.

```yaml
bind: "0.0.0.0"
https_port: 443
shared_443: false # true = один 443 proxy+stealth API по Host (prod); false = split (lab)
shared_443: false # true = один 443 proxy+stealth API по Host (prod); false = split (lab)
domains:
  - "login.example.com"
storage:
  sqlite_path: "./data/phantom.db"
  redis_addr: "127.0.0.1:6379"
  session_ttl_min: 60
tls:
  email: "ops@example.com"
  dns_provider: "cloudflare" # cloudflare|route53|gandi|disabled
  wildcard: true
  autocert: true          # false = только готовые cert/key, выпуска нет
  upstream_tls: default   # chrome = uTLS HelloChrome+H2
api:
  stealth_hostname: "api-internal.example.com"
  ca_file: "./certs/ca.pem"
  cert_file: "./certs/server.pem"
  key_file: "./certs/server-key.pem"
log_level: "info" # debug|info|warn|error
node_id: "" # пусто = hostname; env PHANTOM_NODE_ID (см. specs/multinode.md)
```

Валидация при старте (`config validate`):
- `domains` >= 1, FQDN, без `verdebudget.ru`-подобного хардкода.
- `tls.dns_provider=disabled => tls.wildcard=false`.
- `api.ca_file/cert_file/key_file` существуют если api включен.
- env перекрывает: `PHANTOM_REDIS_ADDR`, `PHANTOM_SQLITE_PATH`, `PHANTOM_LOG_LEVEL`.
