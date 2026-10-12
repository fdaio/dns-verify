// Package render prints an analysed run as a text report.
//
// The default output is meant to be read in one look: a score, four verdicts,
// and what to do next. Everything else is measurement, and measurement only
// appears when it is asked for.
package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/fdaio/dns-verify/internal/analyze"
	"github.com/fdaio/dns-verify/internal/sysdns"
	"github.com/fdaio/dns-verify/internal/term"
)

const (
	// labelWidth is the width of the question column.
	labelWidth = 21
	// stateWidth is the width of the verdict column.
	stateWidth = 9
	// titleWidth is the width the score block is right aligned to.
	titleWidth = 60
	// maxFixes is the number of actions shown before the reader must open the
	// detailed output. A longer list stops being a to-do list.
	maxFixes = 3
)

// Options controls the presentation of one report.
type Options struct {
	// Style colours the status, the grade and the score.
	Style term.Style
	// Verbose adds the measurements behind each verdict.
	Verbose bool
}

// Report writes the report.
func Report(w io.Writer, r analyze.Report, opts Options) error {
	writeHeader(w, r, opts)
	writeAnswers(w, r, opts)
	writeFixes(w, r, opts)
	if !opts.Verbose {
		fmt.Fprintln(w)
		fmt.Fprintln(w, opts.Style.Dim("Run with -v for the measurements behind these verdicts."))
		return nil
	}
	writeDetails(w, r, opts)
	return nil
}

// levelOf maps a verdict onto the palette. The state word is the fastest thing
// to scan in a column, so it carries the colour rather than the sentence next
// to it.
func levelOf(state analyze.State) term.Level {
	switch state {
	case analyze.StateGood:
		return term.LevelGood
	case analyze.StateWarn:
		return term.LevelWarn
	case analyze.StateUnmanaged:
		return term.LevelBad
	default:
		return term.LevelMuted
	}
}

func levelOfGrade(grade analyze.Grade) term.Level {
	switch grade {
	case analyze.GradeGood:
		return term.LevelGood
	case analyze.GradePartial:
		return term.LevelWarn
	case analyze.GradePoor:
		return term.LevelBad
	default:
		return term.LevelMuted
	}
}

func writeHeader(w io.Writer, r analyze.Report, opts Options) {
	grade := r.Grade()
	level := levelOfGrade(grade)
	// The score carries the colour of its grade, because the two always agree
	// and the reader is scanning for one or the other.
	scorePlain := fmt.Sprintf("%d/%d", r.Score(), analyze.MaxScore)
	headlinePlain := scorePlain + "  " + grade.String()

	headline := opts.Style.Level(level, scorePlain) + "  " + opts.Style.Level(level, grade.String())
	if n := r.NotMeasured(); n > 0 {
		note := fmt.Sprintf("(%d NOT MEASURED)", n)
		headlinePlain += "  " + note
		headline += "  " + opts.Style.Dim(note)
	}
	title := opts.Style.Bold("DNS VERIFY")
	fmt.Fprintf(w, "%s%s\n\n", title, padStyled(titleWidth, headlinePlain, headline))
}

func writeAnswers(w io.Writer, r analyze.Report, opts Options) {
	for i, a := range r.Answers {
		// The padding is measured on the plain word, because escape sequences
		// take bytes the column must not count.
		state := padStyled(stateWidth, a.State.String(),
			opts.Style.Level(levelOf(a.State), a.State.String()))
		fmt.Fprintf(w, "%d  %s %s  %s\n",
			i+1, leader(a.Label, labelWidth), state, opts.Style.Dim(a.Hint))
	}
	fmt.Fprintln(w)
}

func writeFixes(w io.Writer, r analyze.Report, opts Options) {
	fixes := r.Fixes()
	if len(fixes) == 0 {
		fmt.Fprintln(w, opts.Style.Level(term.LevelGood, "Nothing to fix."))
		return
	}

	heading := opts.Style.Bold("FIX FIRST")
	if len(fixes) > maxFixes {
		heading += " " + opts.Style.Dim(fmt.Sprintf("(%d more in -v)", len(fixes)-maxFixes))
	}
	fmt.Fprintln(w, heading)
	for i, fix := range fixes {
		if i >= maxFixes {
			return
		}
		// The mark lets a reader scan the list without reading the sentences.
		mark := opts.Style.Level(severityLevel(fix.Severity), markFor(fix.Severity))
		fmt.Fprintf(w, "  %s %d. %s\n", mark, i+1, fix.Text)
		if fix.Command != "" {
			fmt.Fprintf(w, "       %s\n", opts.Style.Dim(fix.Command))
		}
	}
}

// severityLevel maps a fix onto the same palette the verdicts use.
func severityLevel(severity analyze.State) term.Level {
	switch severity {
	case analyze.StateUnmanaged:
		return term.LevelBad
	case analyze.StateWarn:
		return term.LevelWarn
	default:
		return term.LevelMuted
	}
}

// markFor gives each severity a glyph, so the list can be scanned without
// reading the sentences.
func markFor(severity analyze.State) string {
	switch severity {
	case analyze.StateUnmanaged:
		return "\u2717"
	case analyze.StateWarn:
		return "!"
	default:
		return "\u00b7"
	}
}

// writeDetails lists the measurements. Only facts that cannot be derived from
// the verdicts belong here: anything the four lines already imply is noise.
func writeDetails(w io.Writer, r analyze.Report, opts Options) {
	f := r.Facts

	fmt.Fprintln(w)
	fmt.Fprintln(w, opts.Style.Bold("MEASUREMENTS"))
	fmt.Fprintln(w, strings.Repeat("-", titleWidth))

	for i, a := range r.Answers {
		fmt.Fprintf(w, "%d  %s [%s]\n", i+1, a.Question,
			opts.Style.Level(levelOf(a.State), a.State.String()))
		fmt.Fprintf(w, "   %s\n", a.Summary)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, opts.Style.Bold("TUNNEL EXIT"))
	if f.Egress == nil {
		fmt.Fprintln(w, "  not measured")
	} else {
		fmt.Fprintf(w, "  %s via %s\n", f.Egress.Addr, f.Egress.Site)
		if f.EgressOrigin != nil {
			fmt.Fprintf(w, "  network %s %s %s\n",
				f.EgressOrigin, f.EgressOrigin.Country, f.EgressOrigin.Prefix)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, opts.Style.Bold("RESOLVERS"))
	if len(f.Resolvers) == 0 {
		fmt.Fprintln(w, "  none found")
	}
	for _, v := range f.Resolvers {
		fmt.Fprintf(w, "  %-16s %-9s port %-5d %s\n",
			v.Addr, v.Kind, v.Port, resolverNotes(v))
	}
	if len(f.EncryptedProfiles) > 0 {
		fmt.Fprintf(w, "  encrypted profiles in %s: %s\n",
			sysdns.ResolverDir, strings.Join(f.EncryptedProfiles, ", "))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, opts.Style.Bold("PROBES"))
	fmt.Fprintf(w, "  hijack      %s\n", hijackNotes(f))
	fmt.Fprintf(w, "  cleartext   udp %s, tcp %s\n", reachable(f.PlaintextUDP), reachable(f.PlaintextTCP))
	fmt.Fprintf(w, "  fake-ip     %s\n", yesNo(fakeIP(f)))
	fmt.Fprintf(w, "  ipv6 leak   %s\n", ipv6Notes(f))
}

// resolverNotes lists the measurements about one resolver.
func resolverNotes(v analyze.ResolverView) string {
	var notes []string
	if !v.Reachable {
		notes = append(notes, "not reachable")
	}
	if v.Encrypted() {
		notes = append(notes, "encrypted transport")
	}
	if v.FakeIP {
		notes = append(notes, "hands out fake addresses")
	}
	if v.EchoAddr.IsValid() {
		notes = append(notes, "answers from "+v.EchoAddr.String())
	} else if v.EchoErr != nil {
		notes = append(notes, "did not report a source address")
	}
	if v.UpstreamAddr.IsValid() {
		notes = append(notes, "forwarded to "+v.UpstreamAddr.String())
	}
	if len(notes) == 0 {
		return "-"
	}
	return strings.Join(notes, ", ")
}

func hijackNotes(f analyze.Facts) string {
	if len(f.Hijack.Probed) == 0 {
		return "did not complete"
	}
	if f.Hijack.Hijacked() {
		return fmt.Sprintf("%d names probed, %d rewritten into addresses",
			len(f.Hijack.Probed), len(f.Hijack.Answers))
	}
	return fmt.Sprintf("%d names probed, none rewritten", len(f.Hijack.Probed))
}

// ipv6Notes names the addresses that can leave outside the tunnel, because a
// bare "yes" would not tell the reader which ones to look at.
func ipv6Notes(f analyze.Facts) string {
	if len(f.IPv6Bypass) == 0 {
		return "no"
	}
	return "yes (" + strings.Join(f.IPv6Bypass, ", ") + ")"
}

func fakeIP(f analyze.Facts) bool {
	for _, v := range f.Resolvers {
		if v.FakeIP {
			return true
		}
	}
	return false
}

// reachable renders a transport probe result.
func reachable(v bool) string {
	if v {
		return "reachable"
	}
	return "blocked"
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// leader pads a label with dots so the following column starts on one line.
func leader(s string, width int) string {
	if len(s) >= width {
		return s + " "
	}
	return s + " " + strings.Repeat(".", width-len(s)-1)
}

// padLeft right-aligns s in a field of the given width.
func padLeft(width int, s string) string {
	if len(s) >= width {
		return s
	}
	return strings.Repeat(" ", width-len(s)) + s
}

// padStyled right-aligns a styled string using the width of its plain form.
// Padding a coloured string with its own length would count every escape
// sequence as visible, so the two must be kept apart.
func padStyled(width int, plain, styled string) string {
	if len(plain) >= width {
		return styled
	}
	return strings.Repeat(" ", width-len(plain)) + styled
}
