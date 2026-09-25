# Multi-node: shared-Redis топология (frozen v1)

Без gossip-кластера: ноды stateless, общее состояние — Redis.
Локальное на ноде: SQLite-факты, blocklist/lures (ре-seed при старте).

## Что общее (синхронизируется из коробки)
- Сессии: один `redis_addr` на всех нодах. Failover dual-write пишет
  в shared Redis + локальную memory; чтение Redis→memory. Сессия,
  созданная на eu-ноде, валидна на us-ноде.
- `node_id` в каждом событии (`capture.*`, `bot.blocked` -> поле `node`)
  и в `captures.node` — видно какая нода поймала.

## Что локальное (на ноде)
- SQLite (`sqlite_path` свой файл! общий файл по NFS — нет, будет SQLITE_BUSY).
- blocklist/lures в памяти + свой sqlite. Синхронизация банов между нодами —
  вручную: `POST /api/v1/block` на каждую ноду (скрипт в deploy).
  Redis pub/sub для банов — следующим этапом, НЕ v1.

## Паттерн конфигурации
```yaml
# node-eu
node_id: "eu-1"
storage: {sqlite_path: "./data/phantom.db", redis_addr: "redis.internal:6379"}
# node-us: тот же redis_addr, свой sqlite_path и node_id: "us-1"
# Секреты: PHANTOM_API_TOKEN / TELEGRAM_BOT_TOKEN одинаковые или разные —
# одинаковые упрощают единый UI.
```

## Наблюдаемость
- `GET /api/v1/stats` -> {node, phishlets, uptime_s}: опрос каждой ноды.
- Логи с префиксом `node=<id>`.
- Telegram-алерты содержат session/ip; оператор видит ноду в `captures.node`.

## DNS
- Вариант A (простой): разные домены на ноду (eu-login.example.com).
- Вариант B: один домен, external DNS с geo-routing (Cloudflare/Route53).

## Честные ограничения v1
- Нет auto-discovery и leader-election (не нужны: координации нет).
- Failover при смерти Redis: нода живет на memory, сессии между нодами
  расходятся до восстановления Redis (dual-write продолжается best-effort).
- Lure uses-счетчики (одноразовые) локальны: одноразовая приманка,
  открытая на двух нодах одновременно, может сработать дважды.
  Для строгой одноразовости — шардить lure-пути по нодам.
