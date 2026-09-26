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
		case "/api/v1/phishlets-check/a":
			_, _ = w.Write([]byte(`[{"host":"o.u.test","http":200,"bytes":10,"hits":["x"],"misses":[]}]`))
		case "/api/v1/captures":
			_, _ = w.Write([]byte(`[{"session":"sess123456","kind":"creds","node":"n1"}]`))
		case "/api/v1/campaigns":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`[{"id":"c1","name":"op","phishlet":"a","status":"running","sent":2,"opened":1,"clicked":1,"submitted":0,"total":2}]`))
				return
			}
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"id":"c1"}`))
		case "/api/v1/campaigns/c1/targets":
			_, _ = w.Write([]byte(`{"added":2}`))
		case "/api/v1/campaigns/c1/launch":
			_, _ = w.Write([]byte(`{"targets":[{"email":"a@x.com","lure":"/l/x"}]}`))
		case "/api/v1/campaigns/c1/report":
			_, _ = w.Write([]byte("# Campaign op\n\n| email |\n"))
		case "/api/v1/campaigns/c1/send":
			_, _ = w.Write([]byte(`{"sent":2}`))
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

func TestCampClient(t *testing.T) {
	srv := fakeAPI()
	defer srv.Close()
	c := &Client{Base: srv.URL, Stealth: "s3cr3t"}
	list, err := c.ListCampaigns()
	if err != nil || len(list) != 1 || list[0].Total != 2 {
		t.Fatalf("camps: %+v %v", list, err)
	}
	id, err := c.CreateCampaign("op", "a", 60, 1, 0)
	if err != nil || id != "c1" {
		t.Fatalf("create: %q %v", id, err)
	}
	if n, err := c.AddTargets(id, []string{"a@x.com"}); err != nil || n != 2 {
		t.Fatalf("targets: %d %v", n, err)
	}
	tg, err := c.LaunchCampaign(id)
	if err != nil || len(tg) != 1 || tg[0].Lure != "/l/x" {
		t.Fatalf("launch: %+v %v", tg, err)
	}
	if n, err := c.SendCampaign(id, "s", "b", "https://m.test"); err != nil || n != 2 {
		t.Fatalf("send: %d %v", n, err)
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

func TestCheckCapturesClient(t *testing.T) {
	srv := fakeAPI()
	defer srv.Close()
	c := &Client{Base: srv.URL, Stealth: "s3cr3t"}
	hc, err := c.CheckPhishlet("a")
	if err != nil || len(hc) != 1 || hc[0].HTTP != 200 || len(hc[0].Hits) != 1 {
		t.Fatalf("check: %+v %v", hc, err)
	}
	caps, err := c.Captures()
	if err != nil || len(caps) != 1 || caps[0].Kind != "creds" {
		t.Fatalf("captures: %+v %v", caps, err)
	}
}
