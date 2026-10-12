//go:build linux

package term

import "syscall"

// readTermios is the ioctl that reads the terminal attributes on Linux. The
// request differs from the BSD one, so the value cannot be shared.
const readTermios = syscall.TCGETS
