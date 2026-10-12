//go:build darwin || linux

package term

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal reports whether the file is attached to a terminal.
//
// Reading the terminal attributes is the only way to tell a terminal from a pipe
// without consuming from the stream.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	var attr syscall.Termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(),
		uintptr(readTermios), uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
	return errno == 0
}
