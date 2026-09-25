package detector

import (
	"net/http"
	"testing"
)

func TestAnalyze(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://x/", nil)
	r.Header.Set("User-Agent", "curl/8")
	f := Analyze(r, "")
	if f.Score < 60 || len(f.Reasons) == 0 {
		t.Fatalf("bad finding: %+v", f)
	}
}
