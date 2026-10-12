package term

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// spinnerFrames rotate to show that the process is alive while a probe waits.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinnerInterval is how often the frame advances. Slow enough to read, fast
// enough that a waiting process looks busy.
const spinnerInterval = 90 * time.Millisecond

// barWidth is the number of cells the bar draws.
const barWidth = 20

// Progress draws a single line that is rewritten in place.
//
// Everything before the stage name keeps a fixed width for the whole run, so a
// stage name of a different length only grows the end of the line. Nothing
// before it can move, which is what stops the bar from jumping sideways.
type Progress struct {
	mu      sync.Mutex
	w       io.Writer
	style   Style
	enabled bool

	label string
	done  int
	// total is the number of steps in the whole run, taken from the first stage
	// that knows it. It stays zero until then.
	total   int
	frame   int
	written bool
	closed  bool
}

// NewProgress returns a progress line for the stream. A disabled progress line
// accepts every call and writes nothing.
func NewProgress(w io.Writer, env Env) *Progress {
	return &Progress{w: w, style: NewStyle(env.Color), enabled: env.Progress}
}

// Enabled reports whether the line draws anything.
func (p *Progress) Enabled() bool { return p != nil && p.enabled }

// Start names the current stage. The total is the size of the whole run, not of
// the stage, and the count carries over from the stages already done, so the
// bar only ever moves forward.
//
// A stage that runs before the total is known reports zero. The first stage to
// report a real total sets it, and a later disagreement is ignored, because the
// line is laid out against one figure.
func (p *Progress) Start(label string, total int) {
	if !p.Enabled() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.label = label
	if p.total == 0 && total > 0 {
		p.total = total
	}
	p.frame = 0
	p.draw()
}

// Advance completes one unit of work.
func (p *Progress) Advance() {
	if !p.Enabled() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.done++
	p.frame = 0
	p.draw()
}

// Spin advances the spinner without changing the count. The check calls it on a
// timer so a stage that waits on a slow resolver still looks alive.
func (p *Progress) Spin() {
	if !p.Enabled() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.frame = (p.frame + 1) % len(spinnerFrames)
	p.draw()
}

// Finished clears the line so the report starts on a clean row. It must run
// however the check ended, including on an interrupt, or the leftover row sits
// above the report.
func (p *Progress) Finished() {
	if !p.Enabled() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}
	p.closed = true
	if !p.written {
		return
	}
	// Erase the row and return the cursor to its start before the report prints.
	_, _ = io.WriteString(p.w, "\r\x1b[2K")
	p.written = false
}

func (p *Progress) draw() {
	if p.closed {
		return
	}

	// The bar has a fixed width, so everything up to and including it starts on
	// the same column whatever the stage is called.
	line := p.style.Wrap("\x1b[36m", spinnerFrames[p.frame]) + " " +
		p.style.Wrap(seqDim, bar(percent(p.done, p.total), barWidth)) + "  " +
		p.label
	// The count goes last because it is the only field that can appear and
	// disappear, and nothing follows it that could move.
	if p.total > 0 {
		line += "  " + p.style.Wrap(seqDim, p.count())
	}

	_, _ = io.WriteString(p.w, "\r\x1b[2K"+line)
	p.written = true
}

// count renders the completed steps over the total.
func (p *Progress) count() string {
	return fmt.Sprintf("%d/%d", min(p.done, p.total), p.total)
}

// percent clamps the completed steps into a whole number from 0 to 99, so the
// bar always shows one cell still to fill and never reads as finished.
func percent(done, total int) int {
	if total <= 0 {
		return 0
	}
	value := done * 100 / total
	if value < 0 {
		return 0
	}
	if value > 99 {
		return 99
	}
	return value
}

// Ticker drives the spinner while a check runs.
type Ticker struct {
	stop chan struct{}
}

// StartTicker advances the spinner until Stop is called. It returns a nil
// ticker when the line draws nothing, so the caller needs no branch.
func (p *Progress) StartTicker() *Ticker {
	if !p.Enabled() {
		return nil
	}
	t := &Ticker{stop: make(chan struct{})}
	go func() {
		for {
			select {
			case <-t.stop:
				return
			case <-time.After(spinnerInterval):
				p.Spin()
			}
		}
	}()
	return t
}

// Stop ends the spinner.
func (t *Ticker) Stop() {
	if t == nil {
		return
	}
	close(t.stop)
}
