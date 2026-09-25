# ADR-001: Greenfield Phantom v2 (2026)

Дата: 2026-09-21
Статус: frozen

## Контекст
Старый `phantom-proxy` (форк Evilginx2) имеет сломанный core (`proxyHandler return nil`),
битую кодировку, дубли config, секреты в гите, кашу `sqlite+postgres+BuntDB`, лишний `go-ethereum`.
Патчить нельзя.

## Решение
Greenfield модульный монолит, один бинарь `phantom`:
- `std net/http` ReverseProxy, не Fiber (долгоживучесть, HTTP/3/ECH).
- `SQLite (конфиг/луры) + Redis (сессии с TTL)`. Никакого postgres на MVP.
- Сначала CLI (как Evilginx), Web позже — чтобы не переделывать API 3 раза.
- Daemon + локальный CLI по mTLS stealth API на 443 (паритет Pro).

## Non-goals MVP
- No Vishing/Twilio, no ГОСТ, no go-ethereum, no 8-сервисов compose.
- No Evilpuppet на MVP (только интерфейс).

## Паритет Evilginx Pro (порядок)
1. Lures/Sessions/Blacklist + Phishlets 2.0 + multidomain
2. Wildcard TLS (ACME DNS-01) + External DNS (Cloudflare/Route53/Gandi)
3. Botguard (JA4+JS) + JS-obfuscation + Website Spoofing
4. Stealth API mTLS + autodeploy
5. Evilpuppet последним
