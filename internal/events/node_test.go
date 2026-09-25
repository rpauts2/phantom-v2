package events

import (
	"context"
	"testing"
)

type memDB struct {
	lastSess, lastKind, lastNode string
	n                            int
}

func (m *memDB) InsertCaptureNode(sess, kind, node string) error {
	m.lastSess, m.lastKind, m.lastNode = sess, kind, node
	m.n++
	return nil
}

func TestNodeInject(t *testing.T) {
	db := &memDB{}
	p := &Persistent{Inner: New(), DB: db, NodeID: "eu-1"}
	ch := p.Inner.Subscribe("capture.creds", 4)
	if err := p.Publish(context.Background(), "capture.creds",
		map[string]string{"session": "s1", "phishlet": "m1"}); err != nil {
		t.Fatal(err)
	}
	if db.lastNode != "eu-1" || db.lastSess != "s1" || db.n != 1 {
		t.Fatalf("db not stamped: %+v", db)
	}
	select {
	case v := <-ch:
		if v.(map[string]string)["node"] != "eu-1" {
			t.Fatalf("event not stamped: %v", v)
		}
	default:
		t.Fatal("no event")
	}
}
