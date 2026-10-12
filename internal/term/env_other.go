//go:build !darwin && !linux

package term

import "os"

// isTerminal reports false on a system where the terminal attribute request
// cannot be named. The tool does not run here, but the package must still build,
// so the probe stays a plain file rather than a syscall.
func isTerminal(*os.File) bool { return false }
