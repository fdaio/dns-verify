//go:build darwin

package term

import "syscall"

// readTermios is the ioctl that reads the terminal attributes on macOS.
const readTermios = syscall.TIOCGETA
