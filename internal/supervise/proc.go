// Package supervise — управление локальным сервером из меню.
// Старт (фон, лог в файл, pid-файл), стоп, статус, хвост лога.
// Одно окно вместо двух: `phantom -menu` поднимает всё сам.
package supervise

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Paths возвращает пути pid/log рядом с бинарником (или cwd).
func Paths() (dir, pid, log string) {
	exe, err := os.Executable()
	if err != nil {
		dir, _ = os.Getwd()
	} else {
		dir = filepath.Dir(exe)
	}
	return dir, filepath.Join(dir, "phantom.pid"), filepath.Join(dir, "phantom.log")
}

// Alive проверяет процесс из pid-файла.
func Alive() (int, bool) {
	_, pidFile, _ := Paths()
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	if !alive(pid) {
		return 0, false
	}
	return pid, true
}

// Health дергает /health API.
func Health(apiBase string) bool {
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Get(strings.TrimSuffix(apiBase, "/") + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// Status: "run" (процесс+API), "half" (процесс без API), "down".
func Status(apiBase string) (string, int) {
	pid, alive := Alive()
	if !alive {
		return "down", 0
	}
	if Health(apiBase) {
		return "run", pid
	}
	return "half", pid
}

// Start поднимает сервер фоном. args — флаги phantom (без -menu).
func Start(exe string, args []string) (int, error) {
	if _, alive := Alive(); alive {
		return 0, fmt.Errorf("уже запущен (stop сначала)")
	}
	_, pidFile, logFile := Paths()
	lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer lf.Close()
	cmd := exec.Command(exe, args...)
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}

// Stop гасит процесс из pid-файла.
func Stop() error {
	_, pidFile, _ := Paths()
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("не запущен (нет pid)")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return err
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := p.Kill(); err != nil {
		return err
	}
	_ = os.Remove(pidFile)
	return nil
}

// Tail возвращает последние n строк лога.
func Tail(n int) string {
	_, _, logFile := Paths()
	b, err := os.ReadFile(logFile)
	if err != nil {
		return "лог пуст: " + err.Error()
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
