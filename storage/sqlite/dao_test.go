package sqlite

import "testing"

func TestDAOPersist(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InsertLure("m1", "/l/1"); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertBlock("1.1.1.1", "test"); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertSession("s1", "m1", "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertCapture("s1", "creds"); err != nil {
		t.Fatal(err)
	}
	lures, err := db.ListLures()
	if err != nil || lures["/l/1"] != "m1" {
		t.Fatalf("lures: %v %v", lures, err)
	}
	blocks, err := db.ListBlocks()
	if err != nil || blocks["1.1.1.1"] == "" {
		t.Fatalf("blocks: %v %v", blocks, err)
	}
	n, err := db.CountCaptures()
	if err != nil || n != 1 {
		t.Fatalf("captures: %d %v", n, err)
	}
}

func TestNodeColumn(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InsertCaptureNode("s9", "creds", "eu-1"); err != nil {
		t.Fatal(err)
	}
	var node string
	if err := db.sql.QueryRow(`SELECT node FROM captures WHERE session_id='s9'`).Scan(&node); err != nil {
		t.Fatal(err)
	}
	if node != "eu-1" {
		t.Fatalf("node lost: %q", node)
	}
	// Миграция идемпотентна: повторный Open старой базы не падает.
	if _, err := db.sql.Exec(`ALTER TABLE captures ADD COLUMN node TEXT DEFAULT ''`); err == nil {
		t.Fatal("second alter must fail (column exists)")
	}
}
