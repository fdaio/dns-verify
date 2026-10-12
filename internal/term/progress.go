package term

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// spinnerFrames rotate to show that the process is alive while a probe waits.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinnerInterval is how often the frame advances. Slow enough to read, fast
// enough that a waiting process looks busy.
const spinnerInterval = 90 * time.Millisecond

// Progress draws a single line that is rewritten in place.
//
// Every method is safe to call when the stream cannot show it, in which case
// nothing is written. The caller therefore never has to branch on the terminal.
type Progress struct {
	mu      sync.Mutex
	w       io.Writer
	style   Style
	enabled bool

	label string
	done  int
	total int
	frame int
	// written records that a row is currently on screen. It is separate from
	// dirty, which only says something changed since the last draw, because a
	// line that is already up to date still has to be erased at the end.
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

// Start names the current stage and resets the count for it. The bar covers one
// stage at a time, because the stages measure different things and adding them
// together would make the bar jump backwards between them.
func (p *Progress) Start(label string, total int) {
	if !p.Enabled() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.label = label
	p.total = total
	p.done = 0
	p.frame = 0
	p.draw()
}

// Advance completes one unit of the current stage. It satisfies the observer
// interface of the check, so the check never names a terminal type.
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

	spinner := p.style.Wrap("\x1b[36m", spinnerFrames[p.frame])
	label := p.label
	if p.total > 1 {
		label = fmt.Sprintf("%s %d/%d", label, min(p.done, p.total), p.total)
	}
	count := ""
	if p.total > 0 {
		count = p.style.Wrap(seqDim, "  "+bar(percent(p.done, p.total), 20))
	}
	_, _ = io.WriteString(p.w, "\r\x1b[2K"+spinner+" "+label+count)
	p.written = true
}

// percent clamps a stage count into a whole number from 0 to 99, so the bar
// always shows one cell still to fill.
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

// PlainLine writes a line to a stream without any terminal handling. The check
// uses it for the report itself.
func PlainLine(w io.Writer, text string) { writeLine(w, strings.TrimRight(text, "\n")) }
