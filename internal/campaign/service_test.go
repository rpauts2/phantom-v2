package campaign

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phantom-v2/phantom/internal/events"
	"github.com/phantom-v2/phantom/internal/lures"
	"github.com/phantom-v2/phantom/internal/mailer"
)

func TestServiceLaunchLures(t *testing.T) {
	cs := NewStore()
	ls := lures.New()
	svc := &Service{Campaigns: cs, Lures: ls, Mail: &mailer.Sender{}}
	c := cs.Create("op", "microsoft365", 60, 1)
	cs.AddTargets(c.ID, []string{"a@x.com", "b@x.com"})
	targets, err := svc.Launch(c.ID)
	if err != nil || len(targets) != 2 {
		t.Fatalf("launch: %v", err)
	}
	// персональные приманки зарегистрированы в lure-сторе
	for _, tg := range targets {
		if _, ok := ls.ResolveSmart(tg.LurePath, "9.9.9.9", false); !ok {
			t.Fatalf("lure missing: %s", tg.LurePath)
		}
		if pid, _ := ls.ResolveSmart(tg.LurePath, "9.9.9.9", false); pid != "" {
			_ = pid
		}
	}
}

func TestTracker(t *testing.T) {
	cs := NewStore()
	tr := Tracker{Campaigns: cs}
	c := cs.Create("op", "m", 0, 1)
	cs.AddTargets(c.ID, []string{"a@x.com"})
	var tid string
	for _, tg := range cs.Targets(c.ID) {
		tid = tg.ID
	}
	// open pixel
	req := httptest.NewRequest("GET", "/__tr/o?tid="+tid, nil)
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/gif" {
		t.Fatalf("pixel: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	// click -> 302 на /l/*
	req2 := httptest.NewRequest("GET", "/__tr/c?tid="+tid+"&to=/l/abc", nil)
	rec2 := httptest.NewRecorder()
	tr.ServeHTTP(rec2, req2)
	if rec2.Code != 302 || !strings.Contains(rec2.Header().Get("Location"), "/l/abc") {
		t.Fatalf("click: %d %s", rec2.Code, rec2.Header().Get("Location"))
	}
	// open redirect наружу — отказ
	req3 := httptest.NewRequest("GET", "/__tr/c?tid="+tid+"&to=https://evil.test", nil)
	rec3 := httptest.NewRecorder()
	tr.ServeHTTP(rec3, req3)
	if rec3.Code != 400 {
		t.Fatalf("open redirect: %d", rec3.Code)
	}
	sent, opened, clicked, _, total := cs.Stats(c.ID)
	if opened != 1 || clicked != 1 || total != 1 || sent != 0 {
		t.Fatalf("stats %d %d %d %d", sent, opened, clicked, total)
	}
}

func TestSubmitAttribution(t *testing.T) {
	cs := NewStore()
	ls := lures.New()
	svc := &Service{Campaigns: cs, Lures: ls, Mail: &mailer.Sender{}}
	c := cs.Create("op", "m", 0, 1)
	cs.AddTargets(c.ID, []string{"a@x.com"})
	targets, _ := svc.Launch(c.ID)
	bus := events.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Watch(ctx, bus)
	// capture с путем персональной приманки -> submit на цель
	_ = bus.Publish(ctx, "capture.creds", map[string]string{
		"session": "s1", "path": targets[0].LurePath,
	})
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, _, _, submitted, _ := cs.Stats(c.ID)
		if submitted == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("submit not attributed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSendAllDry(t *testing.T) {
	cs := NewStore()
	svc := &Service{Campaigns: cs, Lures: lures.New(), Mail: &mailer.Sender{Cfg: mailer.Config{DryRun: true}}}
	c := cs.Create("op", "m", 60, 1)
	cs.AddTargets(c.ID, []string{"a@x.com", "b@x.com"})
	if _, err := svc.Launch(c.ID); err != nil {
		t.Fatal(err)
	}
	n, err := svc.SendAll(c.ID, "Hi {{.Email}}", `<a href="{{.URL}}">go</a>`, "https://m.test")
	if err != nil || n != 2 {
		t.Fatalf("send: %d %v", n, err)
	}
	sent, _, _, _, _ := cs.Stats(c.ID)
	if sent != 2 {
		t.Fatal("sent not marked")
	}
}
