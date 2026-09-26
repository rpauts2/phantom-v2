package campaign

import "testing"

func TestLifecycle(t *testing.T) {
	s := NewStore()
	c := s.Create("Q3 Test!", "microsoft365", 120, 0)
	if c.MaxUses != 1 || c.Status != StatusDraft {
		t.Fatalf("bad create: %+v", c)
	}
	if n := s.AddTargets(c.ID, []string{
		"  A@x.com ", "a@x.com", "bad", "b@x.com",
	}); n != 2 {
		t.Fatalf("add=%d", n)
	}
	targets, err := s.Launch(c.ID)
	if err != nil || len(targets) != 2 {
		t.Fatalf("launch: %v %d", err, len(targets))
	}
	if _, err := s.Launch(c.ID); err == nil {
		t.Fatal("relaunch must fail")
	}
	t0 := targets[0]
	if _, ok := s.TargetByLure(t0.LurePath); !ok {
		t.Fatal("lure resolve broken")
	}
	s.Mark(t0.ID, "sent")
	s.Mark(t0.ID, "open")
	s.Mark(t0.ID, "click")
	s.Mark(t0.ID, "submit")
	s.Mark(t0.ID, "bogus")
	sent, opened, clicked, submitted, total := s.Stats(c.ID)
	if sent != 1 || opened != 1 || clicked != 1 || submitted != 1 || total != 2 {
		t.Fatalf("stats %d %d %d %d %d", sent, opened, clicked, submitted, total)
	}
	// повторный open не двигает время/счетчик
	s.Mark(t0.ID, "open")
	if _, opened2, _, _, _ := s.Stats(c.ID); opened2 != 1 {
		t.Fatal("double open counted")
	}
	if _, err := s.Launch("nope"); err == nil {
		t.Fatal("unknown launch must fail")
	}
	empty := s.Create("e", "x", 0, 0)
	if _, err := s.Launch(empty.ID); err == nil {
		t.Fatal("empty launch must fail")
	}
}

type fakePersist struct {
	camps int
	tgts  int
}

func (f *fakePersist) UpsertCampaign(id, name, phishletID, status string, ttlMin, maxUses int, createdAt int64) error {
	f.camps++
	return nil
}

func (f *fakePersist) UpsertTarget(id, campaignID, email, lure string, sent, opened, clicked, submitted bool) error {
	f.tgts++
	return nil
}

func TestPersistAndTrim(t *testing.T) {
	s := NewStore()
	fp := &fakePersist{}
	s.DB = fp
	c := s.Create("op", "m", 0, 1)
	s.AddTargets(c.ID, []string{"a@x.com"})
	if _, err := s.Launch(c.ID); err != nil {
		t.Fatal(err)
	}
	s.Mark("x", "bogus")
	if fp.camps < 2 || fp.tgts < 1 {
		t.Fatalf("persist calls: %+v", fp)
	}
	// trim: шторм событий по живой цели не растит историю бесконечно
	tids := []string{}
	for _, tg := range s.Targets(c.ID) {
		tids = append(tids, tg.ID)
	}
	for i := 0; i < maxEvents+500; i++ {
		s.Mark(tids[0], "click")
	}
	if n := s.EventsCount(); n > maxEvents {
		t.Fatalf("events unbounded: %d", n)
	}
	// restore
	s2 := NewStore()
	s2.Restore(Campaign{ID: "c9", Name: "r", PhishletID: "m", Status: StatusRunning},
		[]Target{{ID: "t9", CampaignID: "c9", Email: "a@x.com", LurePath: "/l/z"}})
	if _, ok := s2.Get("c9"); !ok {
		t.Fatal("restore camp")
	}
	if _, ok := s2.TargetByLure("/l/z"); !ok {
		t.Fatal("restore target")
	}
}
