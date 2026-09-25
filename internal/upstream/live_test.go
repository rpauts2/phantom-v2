package upstream

import (
	"fmt"
	"io"
	"net/http"
	"testing"
)

// Прямой H2-запрос нашим транспортом: какой Host увидит httpbin?
func TestLiveH2Host(t *testing.T) {
	if testing.Short() {
		t.Skip("needs internet")
	}
	req, _ := http.NewRequest("GET", "https://httpbin.org/get", nil)
	req.Host = "rewritten.example.com"
	req.Header.Set("User-Agent", "probe")
	resp, err := Default().RoundTrip(req)
	if err != nil {
		t.Skipf("no internet: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Printf("HTTPBIN SAYS: %s\n", string(b))
}
