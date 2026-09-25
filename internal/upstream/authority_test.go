package upstream

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Куда реально смотрит H2-транспорт: req.Host или URL.Host?
func TestH2AuthoritySource(t *testing.T) {
	var gotHost, gotURLHost string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotURLHost = r.URL.Host
		w.WriteHeader(200)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	tr := Default()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, _ := http.NewRequest("GET", srv.URL+"/x", nil)
	req.Host = "rewritten.example.com"
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	t.Logf("server saw r.Host=%q r.URL.Host=%q", gotHost, gotURLHost)
	if gotHost != "rewritten.example.com" {
		t.Fatalf("authority wrong: %q", gotHost)
	}
}
