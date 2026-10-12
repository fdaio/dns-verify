// Package term decides what the output stream can take, and draws progress on
// it.
//
// Everything here is a no-op when the stream is not a terminal, so the same
// code path produces a clean report in a file or a pipeline.
package term

import "os"

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
