package pullsync

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestSyncClonePull(t *testing.T) {
	src := t.TempDir()
	git(t, src, "init")
	git(t, src, "config", "user.email", "t@t")
	git(t, src, "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(src, "a.yaml"), []byte("id: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, src, "add", ".")
	git(t, src, "commit", "-m", "a")

	dst := filepath.Join(t.TempDir(), "phishlets")
	changed, err := Sync(dst, src, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first clone must report changed")
	}
	if _, err := os.Stat(filepath.Join(dst, "a.yaml")); err != nil {
		t.Fatal("a.yaml missing after clone")
	}
	// Без изменений — pull без changed.
	changed, err = Sync(dst, src, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("no-op pull must not report changed")
	}
	// Новый файл в источнике — changed.
	if err := os.WriteFile(filepath.Join(src, "b.yaml"), []byte("id: b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, src, "add", ".")
	git(t, src, "commit", "-m", "b")
	changed, err = Sync(dst, src, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("pull with new file must report changed")
	}
}

func TestSyncGuards(t *testing.T) {
	if _, err := Sync(t.TempDir(), "", time.Minute); err == nil {
		t.Fatal("empty url must fail")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(dir, "https://example.com/r.git", time.Minute); err == nil {
		t.Fatal("non-empty non-git dir must fail")
	}
}

func TestStartLoop(t *testing.T) {
	src := t.TempDir()
	git(t, src, "init")
	git(t, src, "config", "user.email", "t@t")
	git(t, src, "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(src, "a.yaml"), []byte("id: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, src, "add", ".")
	git(t, src, "commit", "-m", "a")
	dst := filepath.Join(t.TempDir(), "ph")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls int32
	var mu sync.Mutex
	done := make(chan struct{})
	go StartLoop(ctx, dst, src, 100*time.Millisecond, func() {
		mu.Lock()
		calls++
		if calls == 1 {
			close(done)
		}
		mu.Unlock()
	})
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("loop never synced")
	}
	cancel()
	time.Sleep(200 * time.Millisecond)
}
