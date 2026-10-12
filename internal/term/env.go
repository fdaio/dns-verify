package term

import (
	"os"
	"syscall"
	"unsafe"
)

// Env describes what the output stream accepts.
type Env struct {
	// Color turns escape sequences on. It is off when the stream is not a
	// terminal, when NO_COLOR is set, or when TERM says the terminal is dumb.
	Color bool
	// Progress turns the live progress line on. It is off when the stream is not
	// a terminal.
	Progress bool
}

// Detect probes the output stream. The environment is read through lookup so a
// test can describe a terminal or a file without changing the process.
func Detect(out *os.File, lookup func(string) (string, bool)) Env {
	env := Env{}
	if !isTerminal(out) {
		return env
	}
	if _, set := lookup("NO_COLOR"); set {
		return env
	}
	if term, ok := lookup("TERM"); ok && term == "dumb" {
		return env
	}
	return Env{Color: true, Progress: true}
}

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
