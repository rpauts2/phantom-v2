# Phantom v2 (2026) — DONE

Лабораторный AiTM-стенд, паритет Evilginx Pro. **Только авторизованный Red Team / обучение в своей лабе.**

## Решение по топологии (принято за тебя)
Split по дефолту: proxy `:8443` + API `:8080`. Prod-режим `shared_443: true` — один 443,
роутинг по Host (stealth hostname -> API, остальное -> proxy). TLS-терминация включена:
lab self-signed, prod ACME DNS-01. API: stealth header + mTLS если ca есть + Bearer
`PHANTOM_API_TOKEN` если задан + rate-limit.

## Быстрый старт
```sh
go run ./cmd/phantom -validate -config config.yaml.example -phishlets configs/phishlets
go run ./cmd/phantom -config config.yaml.example -phishlets configs/phishlets -api 127.0.0.1:8080
curl -H "X-Stealth-Host: api-internal.example.com" http://127.0.0.1:8080/api/v1/stats
curl -H "X-Stealth-Host: api-internal.example.com" http://127.0.0.1:8080/dashboard
# Operator UI в браузере: http://127.0.0.1:8080/ui/dashboard.html
```

## Что доделано (весь план + стратегия 2026)
- Lures/Sessions/Blocklist + Phishlets multidomain + SQLite DAO (lures/smart_lures/sessions/captures/blocklist, рестарт-устойчиво; vault нет по решению)
- Smart Lures: одноразовые burn, TTL, IP-bind, challenge-gate (__fp_ok), `POST /api/v1/lures`, персист sqlite
- MFA: `mfa_tokens` (totp/push/webauthn ceremony relay; приватники origin-bound — фиксируем факт), OAuth-каскад: `Location ?code=/fragment` + JSON access/id/refresh_token
- Wildcard TLS: lab self-signed + prod ACME DNS-01 + терминация ListenAndServeTLS + shared-443 опция
- Upstream 2026: H2-транспорт по дефолту (ForceAttemptHTTP2+ALPN), опция `upstream_tls=chrome` (uTLS HelloChrome+H2, требует H2-апстрим), JA4H-approx (presence-сигнал; wire-порядок недоступен в net/http — честно)
- External DNS: disabled/file/cloudflare real; route53/gandi — интерфейс + честная ошибка
- Botguard JA4 (реальный из TLS; X-JA4 только lab `PHANTOM_TRUST_XJA4=1`) threshold 80 -> spoof + JS полиморф + Website Spoofing + сикьюрити-хедеры
- Behavioral Collector: мышь (count/дистанция), scroll, DOM-тайминг 1.5с, WebGL renderer, скоринг (webdriver/headless + нулевая энтропия)
- Stealth API + mTLS + Bearer + rate-limit + OpenAPI + `/dashboard` + встроенный Operator UI `/ui` (embed, loopback/stealth-host gate) + CLI deploy (scp+systemd, key-only)
- Telegram-бот: алерты CREDS/MFA/TOKEN/BLOCKED с кнопками [Drop session] [Block IP] (только метаданные, секретов нет; токен только env `TELEGRAM_BOT_TOKEN`); `SessionDropper` в Memory/Redis/Failover
- WS-инспектор: accept/dial, инспекция text-фреймов (токены via:ws), ping/pong keepalive, read-limit 4MB, fallback в raw-туннель для не-WS апстрима
- AI-генератор фишлетов: `phantom -gen` (эвристики forms/cookies/mfa + Validate) + опциональный LLM-refine (Ollama/OpenAI-совместимый, ключ env) + `POST /api/v1/phishlets/generate`; Hot-Reload без рестарта (`POST .../reload`, `POST .../phishlets` 201, флаг `-watch-phishlets`)
- Multi-node readiness: `node_id` (hostname/env) в логах, событиях и `captures.node`; сессии shared через общий Redis; паттерн в `specs/multinode.md` (без gossip — stateless ноды)
- Sessions: Failover dual-write Redis+memory (смерть Redis не теряет сессии), создание пишется в sqlite
- EventBus persistent (creds/token/mfa -> sqlite, без plaintext) + metrics per-phishlet + detector-as-code (веса унифицированы с botguard) + rate-limit
- Proxy fidelity: Location/Cookie rewrite (+SameSite/Path), JSON+form creds, sid validate + IP/JA4 bind + Secure, remoteIP/SplitHostPort (IPv6), X-Forwarded-Host fix, WS-туннель с дедлайнами/done-channel, байтовые замены без string-аллокаций
- e2e: upstream httptest -> rewrite + sid + POST без потерь + redirect/cookie/JSON/MFA/OAuth (тесты зеленые)

## Структура
`cmd/phantom core/{proxy,phishlet,session} internal/{config,api,lures,blocklist,dns,botguard,obfuscate,spoof,detector,metrics,puppet,deploy,tls,events,ratelimit,ja4,upstream,webui} storage/{sqlite,redis} specs/ configs/phishlets`
