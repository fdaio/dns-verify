package term

import (
	"strings"
)

// Escape sequences for the attributes the report uses. They are the base ANSI
// set, which every terminal that can show them understands.
const (
	seqReset  = "\x1b[0m"
	seqBold   = "\x1b[1m"
	seqDim    = "\x1b[2m"
	seqRed    = "\x1b[31m"
	seqGreen  = "\x1b[32m"
	seqYellow = "\x1b[33m"
	seqGrey   = "\x1b[90m"
)

// Style turns text on or off. A disabled Style returns the text unchanged, so a
// caller never has to check before colouring.
type Style struct {
	enabled bool
}

// NewStyle returns a Style that emits escape sequences when enabled.
func NewStyle(enabled bool) Style { return Style{enabled: enabled} }

// Enabled reports whether this Style emits escape sequences.
func (s Style) Enabled() bool { return s.enabled }

// Wrap surrounds text with the given attribute and resets after it. An empty
// sequence returns the text untouched, which keeps a disabled Style free of
// stray resets.
func (s Style) Wrap(seq, text string) string {
	if !s.enabled || seq == "" {
		return text
	}
	return seq + text + seqReset
}

// Bold, Dim and the colour helpers are the attributes the report uses.
func (s Style) Bold(text string) string { return s.Wrap(seqBold, text) }
func (s Style) Dim(text string) string  { return s.Wrap(seqDim, text) }

// Level is a severity that maps to one colour. The report uses it instead of
// writing escape sequences, so the palette lives in one place.
type Level int

const (
	// LevelGood marks something that is under control.
	LevelGood Level = iota
	// LevelWarn marks something partly under control.
	LevelWarn
	// LevelBad marks something that is not under control.
	LevelBad
	// LevelMuted marks something that could not be measured.
	LevelMuted
)

// Level paints text with the colour of the severity.
func (s Style) Level(level Level, text string) string {
	return s.Wrap(level.sequence(), text)
}

func (l Level) sequence() string {
	switch l {
	case LevelGood:
		return seqGreen
	case LevelWarn:
		return seqYellow
	case LevelBad:
		return seqRed
	default:
		return seqGrey
	}
}

// Glyphs used by the report and the progress line.
const (
	glyphFull  = "█"
	glyphEmpty = "░"
)

// bar renders a fixed width progress bar as two runs of glyphs.
func bar(percent, width int) string {
	if width < 2 {
		return ""
	}
	filled := percent * width / 100
	if filled > width-1 {
		// The trailing empty cell keeps the bar visibly in progress at 100%,
		// so the last tick does not look like the line stopped early.
		filled = width - 1
	}
	var sb strings.Builder
	sb.Grow(width * 3)
	for range filled {
		sb.WriteString(glyphFull)
	}
	for range width - filled {
		sb.WriteString(glyphEmpty)
	}
	return sb.String()
}
