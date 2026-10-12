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

// Report writes the report. The detailed measurement block is written only when
// verbose is set.
func Report(w io.Writer, r analyze.Report, verbose bool) error {
	writeHeader(w, r)
	writeAnswers(w, r)
	writeFixes(w, r)
	if !verbose {
		fmt.Fprintln(w, "\nRun with -v for the measurements behind these verdicts.")
		return nil
	}
	writeDetails(w, r)
	return nil
}

func writeHeader(w io.Writer, r analyze.Report) {
	title := "DNS VERIFY"
	score := fmt.Sprintf("%d/%d  %s", r.Score(), analyze.MaxScore, r.Grade())
	if n := r.NotMeasured(); n > 0 {
		score += fmt.Sprintf("  (%d NOT MEASURED)", n)
	}
	fmt.Fprintf(w, "%s%s\n\n", title, padLeft(titleWidth, score))
}

func writeAnswers(w io.Writer, r analyze.Report) {
	for i, a := range r.Answers {
		fmt.Fprintf(w, "%d  %s %s  %s\n",
			i+1, leader(a.Label, labelWidth), padLeft(stateWidth, a.State.String()), a.Hint)
	}
	fmt.Fprintln(w)
}

func writeFixes(w io.Writer, r analyze.Report) {
	fixes := r.Fixes()
	if len(fixes) == 0 {
		fmt.Fprintln(w, "Nothing to fix.")
		return
	}

	heading := "FIX FIRST"
	if len(fixes) > maxFixes {
		heading = fmt.Sprintf("FIX FIRST (%d more in -v)", len(fixes)-maxFixes)
	}
	fmt.Fprintln(w, heading)
	for i, fix := range fixes {
		if i >= maxFixes {
			return
		}
		fmt.Fprintf(w, "  %d. %s\n", i+1, fix.Text)
		if fix.Command != "" {
			fmt.Fprintf(w, "     %s\n", fix.Command)
		}
	}
}

// writeDetails lists the measurements. Only facts that cannot be derived from
// the verdicts belong here: anything the four lines already imply is noise.
func writeDetails(w io.Writer, r analyze.Report) {
	f := r.Facts

	fmt.Fprintln(w)
	fmt.Fprintln(w, "MEASUREMENTS")
	fmt.Fprintln(w, strings.Repeat("-", titleWidth))

	for i, a := range r.Answers {
		fmt.Fprintf(w, "%d  %s [%s]\n", i+1, a.Question, a.State)
		fmt.Fprintf(w, "   %s\n", a.Summary)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "TUNNEL EXIT")
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
	fmt.Fprintln(w, "RESOLVERS")
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
	fmt.Fprintln(w, "PROBES")
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
