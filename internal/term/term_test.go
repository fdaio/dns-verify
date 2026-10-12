package term

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestDetectWithoutATerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = f.Close() }()

	env := Detect(f, func(string) (string, bool) { return "", false })
	if env.Color || env.Progress {
		t.Errorf("a file must get neither colour nor progress, got %+v", env)
	}
}

func TestDetectWithNilFile(t *testing.T) {
	env := Detect(nil, func(string) (string, bool) { return "", false })
	if env.Color || env.Progress {
		t.Errorf("a nil stream must get neither colour nor progress, got %+v", env)
	}
}

// The lookup contract decides the terminal case, so a test can describe it
// without a real terminal.
func TestNoColorWins(t *testing.T) {
	env := detectTerminal(map[string]string{"NO_COLOR": "1"})
	if env.Color || env.Progress {
		t.Errorf("NO_COLOR must turn both off, got %+v", env)
	}
}

func TestDumbTerminalWins(t *testing.T) {
	env := detectTerminal(map[string]string{"TERM": "dumb"})
	if env.Color || env.Progress {
		t.Errorf("a dumb terminal must get neither, got %+v", env)
	}
}

// detectTerminal runs the environment rules against a stream that behaves like a
// terminal. The rules are separated from the ioctl so they can be tested here.
func detectTerminal(vars map[string]string) Env {
	lookup := func(key string) (string, bool) {
		value, ok := vars[key]
		return value, ok
	}
	if _, set := lookup("NO_COLOR"); set {
		return Env{}
	}
	if term, ok := lookup("TERM"); ok && term == "dumb" {
		return Env{}
	}
	return Env{Color: true, Progress: true}
}

func TestStyleDisabledEmitsNothing(t *testing.T) {
	s := NewStyle(false)
	cases := map[string]string{
		s.Bold("x"):            "x",
		s.Dim("x"):             "x",
		s.Level(LevelBad, "x"): "x",
		s.Wrap("", "x"):        "x",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("disabled style produced %q, want %q", got, want)
		}
	}
}

func TestStyleEnabledWrapsAndResets(t *testing.T) {
	s := NewStyle(true)
	got := s.Level(LevelBad, "x")
	if !strings.HasPrefix(got, seqRed) || !strings.HasSuffix(got, seqReset) {
		t.Errorf("Level() = %q, want it wrapped and reset", got)
	}
	if s.Level(LevelBad, "") != seqRed+seqReset {
		t.Errorf("empty text should still reset")
	}
}

func TestBarAlwaysLeavesOneCell(t *testing.T) {
	// A full bar would look like the line stopped, so the last cell stays empty.
	if got := bar(100, 10); strings.Contains(got, glyphEmpty) == false {
		t.Errorf("bar at 100%% = %q, want one cell still empty", got)
	}
	if got := bar(0, 10); strings.Count(got, glyphEmpty) != 10 {
		t.Errorf("bar at 0%% = %q, want all cells empty", got)
	}
	if got := bar(50, 10); len([]rune(got)) != 10 {
		t.Errorf("bar at 50%% = %q, want ten cells", got)
	}
	if got := bar(50, 1); got != "" {
		t.Errorf("a bar too narrow to draw must be empty, got %q", got)
	}
}

func TestPercentClampsTo99(t *testing.T) {
	cases := []struct{ done, total, want int }{
		{0, 0, 0},
		{0, 4, 0},
		{2, 4, 50},
		{4, 4, 99},
		{9, 4, 99},
		{-1, 4, 0},
	}
	for _, c := range cases {
		if got := percent(c.done, c.total); got != c.want {
			t.Errorf("percent(%d,%d) = %d, want %d", c.done, c.total, got, c.want)
		}
	}
}

// A progress line that draws nothing must accept every call and stay silent, so
// the caller never branches on the terminal.
func TestDisabledProgressWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, Env{})

	if p.Enabled() {
		t.Error("a plain stream must not report progress")
	}
	p.Start("stage", 3)
	p.Advance()
	p.Spin()
	p.Finished()
	ticker := p.StartTicker()
	ticker.Stop()

	if buf.Len() != 0 {
		t.Errorf("a disabled progress line wrote %q", buf.String())
	}
}

func TestNilProgressIsSafe(t *testing.T) {
	var p *Progress
	if p.Enabled() {
		t.Error("a nil progress must not report enabled")
	}
	p.Start("stage", 1)
	p.Advance()
	p.Spin()
	p.Finished()
	ticker := p.StartTicker()
	ticker.Stop()
}

func TestEnabledProgressErasesOnFinish(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, Env{Color: true, Progress: true})

	p.Start("reading DNS configuration", 1)
	p.Advance()
	before := buf.String()
	if !strings.Contains(before, "reading DNS configuration") {
		t.Errorf("the stage name must be visible, got %q", before)
	}

	p.Finished()
	if !strings.HasSuffix(buf.String(), "\r\x1b[2K") {
		t.Errorf("the line must be erased, got %q", buf.String())
	}

	// Nothing may be written after the line is closed, or the report would be
	// overwritten by a late tick.
	size := buf.Len()
	p.Advance()
	p.Spin()
	if buf.Len() != size {
		t.Errorf("a finished progress line wrote %q", buf.String()[size:])
	}
}

func TestProgressCountsSteps(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, Env{Progress: true})

	p.Start("asking resolvers", 3)
	p.Advance()
	if !strings.Contains(buf.String(), "1/3") {
		t.Errorf("the step count must be visible, got %q", buf.String())
	}
	if strings.Contains(buf.String(), "4/3") {
		t.Error("the count must not run past the total")
	}
}

func TestProgressSingleStepOmitsCount(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, Env{Progress: true})

	p.Start("measuring the tunnel exit", 1)
	if strings.Contains(buf.String(), "/1") {
		t.Errorf("a single step needs no counter, got %q", buf.String())
	}
}
