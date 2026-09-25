package events

import (
	"context"
	"testing"
)

func TestPublishSubscribe(t *testing.T) {
	b := New()
	ch := b.Subscribe("capture.creds", 4)
	if err := b.Publish(context.Background(), "capture.creds", "x"); err != nil {
		t.Fatal(err)
	}
	select {
	case v := <-ch:
		if v != "x" {
			t.Fatal("bad payload")
		}
	default:
		t.Fatal("no event")
	}
}
