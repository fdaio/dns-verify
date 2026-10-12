//go:build !darwin && !linux

package term

// readTermios has no value on this platform, so isTerminal must not ask for
// terminal attributes it cannot name. The check runs on macOS only, and this
// file exists so the package still builds elsewhere.
const readTermios = 0
