# Phishgen + Hot-Reload (frozen v1)

## Генератор
`phantom -gen -gen-origin login.acme.com -gen-domain phish.test -gen-id acme
[-gen-sub login] [-gen-html page.html] [-gen-out acme.yaml]
[-gen-llm http://localhost:11434/v1] [-gen-model llama3]`

Слой 1 (детерминированный, всегда): парсинг origin-хоста, sub_filters
origin->phish, creds_map из `<input type/name>` (password/email/tel),
auth_tokens из cookie/localStorage-имен + token-like идентификаторов,
mfa_tokens по маркерам (totp/webauthn/push), lure `/l/<id>-01`.
Выход валидируется `phishlet.Validate` — невалидное не возвращается.

Слой 2 (опциональный LLM-refine): OpenAI-совместимый `/v1/chat/completions`
(Ollama/OpenAI/LiteLLM), ключ только env `LLM_API_KEY`. Промпт запрещает
менять id/version/hosts/lure — только токены/creds_map/mfa/sub_filters.
Ответ проверяется спеком; при любой ошибке — эвристика + лог.

API: `POST /api/v1/phishlets/generate` {origin, domain, id, sub?, html?} -> YAML.

## Hot-Reload (без рестарта)
- `Store.Reload(dir)`: атомарный swap, битый YAML не трогает живой стор.
- `Store.UpsertYAML(data)`: замена по ID со чисткой старых host-ключей,
  конфликт чужого ID -> ошибка без мутации.
- `POST /api/v1/phishlets/reload` -> 204 (перечитывает dir + ре-seed lures).
- `POST /api/v1/phishlets` (raw YAML) -> 201 id (валидация + запись `<id>.yaml`).
- Флаг `-watch-phishlets`: опрос dir каждые 15с, reload при изменении mtime.
