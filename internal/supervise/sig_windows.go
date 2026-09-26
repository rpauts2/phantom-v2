//go:build windows

package supervise

import (
	"os/exec"
	"strconv"
	"strings"
)

// Windows: сигнал 0 не поддерживается — проверяем через tasklist.
func alive(pid int) bool {
	out, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid), "/NH").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), strconv.Itoa(pid))
}
