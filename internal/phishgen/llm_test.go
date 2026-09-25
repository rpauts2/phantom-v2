package phishgen

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const fakeRefined = `id: acme
version: 2
base_domains: ["phish.test"]
proxy_hosts: [{phish_sub: "login", orig_sub: "login", domain: "acme.com", is_landing: true}]
auth_tokens: [{domain: ".acme.com", keys: ["ESTSAUTH", "SID"]}]
creds_map: [{key: "login", search: "user_email"}, {key: "passwd", search: "user_pass"}]
lure_path: "/l/acme-01"
enabled: true
`

func TestRefineOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, _ := json.Marshal(map[string]any{
			"choices": []any{map[string]any{"message": map[string]string{"content": fakeRefined}}},
		})
		_, _ = w.Write(resp)
	}))
	defer srv.Close()
	out, err := RefineViaLLM("id: acme\nversion: 2\n", LLMConfig{BaseURL: srv.URL, Model: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ESTSAUTH") {
		t.Fatalf("bad refine:\n%s", out)
	}
}

func TestRefineInvalidRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"id: [broken"}}]}`))
	}))
	defer srv.Close()
	if _, err := RefineViaLLM("x", LLMConfig{BaseURL: srv.URL, Model: "test"}); err == nil {
		t.Fatal("invalid refine must fail (caller keeps heuristic)")
	}
}

func TestRefineNoConfig(t *testing.T) {
	if _, err := RefineViaLLM("x", LLMConfig{}); err == nil {
		t.Fatal("empty config must fail")
	}
}
