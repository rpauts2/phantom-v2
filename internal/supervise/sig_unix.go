//go:build !windows

package supervise

import (
	"os"
	"syscall"
)

func alive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
