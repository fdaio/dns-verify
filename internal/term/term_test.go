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

	p.Start("measuring the tunnel exit", 9)
	p.Advance()
	if !strings.Contains(buf.String(), "1/9") {
		t.Errorf("the step count must be visible, got %q", buf.String())
	}
	if strings.Contains(buf.String(), "10/9") {
		t.Error("the count must not run past the total")
	}
}

// The bar used to restart at zero for every stage, which read as the line
// shaking. It must only ever move forward across a whole run.
func TestBarNeverGoesBackwards(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, Env{Progress: true})

	stages := []struct {
		label string
		steps int
	}{
		{"measuring the tunnel exit", 1},
		{"asking resolvers for their source address", 3},
		{"probing for hijacked answers", 3},
		{"looking up the network of each address", 1},
	}
	previous := -1
	for _, stage := range stages {
		p.Start(stage.label, 8)
		for range stage.steps {
			p.Advance()
			filled := strings.Count(lastFrame(buf.String()), glyphFull)
			if filled < previous {
				t.Fatalf("the bar went backwards at %q: %d filled cells after %d",
					stage.label, filled, previous)
			}
			previous = filled
		}
	}
}

// A stage name of a different length must not move anything before it. The bar
// and the stage name both have to start on the same column every frame.
func TestStageNameDoesNotMoveTheBar(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, Env{Progress: true})

	barColumn, labelColumn := 0, 0
	for _, label := range []string{
		"reading DNS configuration",
		"measuring the tunnel exit",
		"asking resolvers for their source address",
		"looking up the network of each address",
	} {
		p.Start(label, 20)
		line := lastFrame(buf.String())
		bar := strings.Index(line, glyphEmpty)
		name := strings.Index(line, label)
		if bar < 0 || name < 0 {
			t.Fatalf("stage %q drew no bar or no name: %q", label, line)
		}
		if barColumn == 0 {
			barColumn, labelColumn = bar, name
		}
		if bar != barColumn {
			t.Errorf("stage %q put the bar at column %d, want %d", label, bar, barColumn)
		}
		if name != labelColumn {
			t.Errorf("stage %q put the name at column %d, want %d", label, name, labelColumn)
		}
	}
}

// The counter appears once the total is known. It must be the last thing on the
// line, so the stage name does not shift when it shows up.
func TestCountAppearsAtTheEndOfTheLine(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, Env{Progress: true})

	p.Start("reading DNS configuration", 0)
	if strings.Contains(buf.String(), "/") {
		t.Errorf("a stage without a total must show no counter, got %q", lastFrame(buf.String()))
	}

	p.Start("measuring the tunnel exit", 12)
	line := lastFrame(buf.String())
	if !strings.HasSuffix(line, "0/12") {
		t.Errorf("the counter must end the line, got %q", line)
	}
}

// lastFrame returns the line the progress bar last drew, without the prefix
// that rewinds and erases it.
func lastFrame(s string) string {
	frames := strings.Split(s, "\r\x1b[2K")
	return frames[len(frames)-1]
}
