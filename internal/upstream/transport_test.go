package upstream

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultH2(t *testing.T) {
	// H2-транспорт обязан говорить и с HTTP/1.1-апстримом (fallback).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	tr := Default()
	if tr == nil {
		t.Fatal("nil transport")
	}
	req, _ := http.NewRequest("GET", srv.URL, nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestChromeBuilds(t *testing.T) {
	tr := ChromeTransport()
	if tr == nil || tr.DialTLSContext == nil {
		t.Fatal("chrome transport broken")
	}
}
