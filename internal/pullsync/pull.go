// Package pullsync — синхронизация курируемой DB фишлетов (Evilginx Pro паритет).
// `phantom -phishlets-pull <git-url>`: clone в dir если пусто, иначе pull.
// После синка вызывающий дергает store.Reload (main делает сам).
package pullsync

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Sync клонирует (первый раз) или подтягивает (дальше) репозиторий в dir.
// Возвращает changed=true если состав *.yaml изменился.
func Sync(dir, url string, timeout time.Duration) (changed bool, err error) {
	if url == "" {
		return false, fmt.Errorf("pullsync: empty url")
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	before, _ := sig(dir)
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		if err := run(timeout, "git", "-C", dir, "pull", "--ff-only"); err != nil {
			return false, fmt.Errorf("pull: %w", err)
		}
	} else {
		entries, _ := os.ReadDir(dir)
		if len(entries) > 0 {
			return false, fmt.Errorf("pullsync: dir %q not empty and not a git repo (move files first)", dir)
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return false, err
		}
		if err := run(timeout, "git", "clone", url, dir); err != nil {
			return false, fmt.Errorf("clone: %w", err)
		}
	}
	after, _ := sig(dir)
	return before != after, nil
}

func run(timeout time.Duration, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.WaitDelay = timeout
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return fmt.Errorf("timeout %s", timeout)
	}
}

func sig(dir string) (string, error) {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	var sb []byte
	for _, f := range matches {
		if fi, err := os.Stat(f); err == nil {
			sb = append(sb, []byte(f+fi.ModTime().String())...)
		}
	}
	return string(sb), nil
}

// StartLoop крутит Sync по тикеру: при changed зовет onChange (обычно store.Reload).
// Останавливается по ctx. Первый синк — сразу.
func StartLoop(ctx context.Context, dir, url string, every time.Duration, onChange func()) {
	if every <= 0 {
		return
	}
	doSync := func() {
		changed, err := Sync(dir, url, 90*time.Second)
		if err != nil {
			return
		}
		if changed && onChange != nil {
			onChange()
		}
	}
	doSync()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			doSync()
		}
	}
}
