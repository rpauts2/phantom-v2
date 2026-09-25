package puppet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHttpTelemetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "lab")
		_, _ = w.Write([]byte(`<html><head><title>Hi</title></head></html>`))
	}))
	defer srv.Close()
	p := HttpTelemetry{}
	s, err := p.FetchTelemetry(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if s == "" {
		t.Fatal("empty telemetry")
	}
}
