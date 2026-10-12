package render

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/fdaio/dns-verify/internal/analyze"
	"github.com/fdaio/dns-verify/internal/probe"
	"github.com/fdaio/dns-verify/internal/sysdns"
	"github.com/fdaio/dns-verify/internal/term"
)

func renderText(t *testing.T, facts analyze.Facts, opts Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Report(&buf, analyze.Build(facts), opts); err != nil {
		t.Fatalf("Report: %v", err)
	}
	return buf.String()
}

func plain(t *testing.T, facts analyze.Facts) string {
	t.Helper()
	return renderText(t, facts, Options{})
}

// The default output is meant to be read in one look, so it must stay short.
func TestDefaultOutputIsShort(t *testing.T) {
	out := plain(t, worstCaseFacts())

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) > 20 {
		t.Errorf("default output is %d lines, want at most 20:\n%s", len(lines), out)
	}
	for _, want := range []string{"2/10", "NOT MANAGED", "FIX FIRST"} {
		if !strings.Contains(out, want) {
			t.Errorf("the headline is missing %q:\n%s", want, out)
		}
	}
}

// A stream that cannot show colour must receive no escape sequence at all. A
// single stray reset is enough to corrupt a file or a log line.
func TestPlainStreamHasNoEscapeSequences(t *testing.T) {
	out := plain(t, sampleFacts())
	if strings.Contains(out, "\x1b") {
		t.Errorf("the plain output carries an escape sequence:\n%q", out)
	}
}

func TestPlainStreamMatchesColouredStream(t *testing.T) {
	facts := sampleFacts()
	plainOut := plain(t, facts)
	coloured := renderText(t, facts, Options{Style: term.NewStyle(true)})

	// Colour only inserts sequences around existing text, so removing them from
	// the coloured output must reproduce the plain one exactly.
	stripped := stripEscapes(coloured)
	if stripped != plainOut {
		t.Errorf("colour changed the text:\n--- plain ---\n%s\n--- stripped ---\n%s", plainOut, stripped)
	}
}

func TestColouredStreamMarksEveryVerdict(t *testing.T) {
	out := renderText(t, worstCaseFacts(), Options{Style: term.NewStyle(true)})

	for _, want := range []string{"\x1b[31m", "\x1b[33m", "\x1b[0m"} {
		if !strings.Contains(out, want) {
			t.Errorf("the coloured output is missing %q:\n%q", want, out)
		}
	}
	if !strings.Contains(out, "\x1b[31m") {
		t.Errorf("an unmanaged question must read as an error:\n%q", out)
	}
}

// The score and the grade always agree, so they must share one colour.
func TestScoreCarriesTheGradeColour(t *testing.T) {
	cases := []struct {
		facts analyze.Facts
		seq   string
	}{
		{sampleFacts(), "\x1b[33m"},
		{controlledFacts(), "\x1b[32m"},
		{worstCaseFacts(), "\x1b[31m"},
		{analyze.Facts{}, "\x1b[90m"},
	}
	for _, c := range cases {
		out := renderText(t, c.facts, Options{Style: term.NewStyle(true)})
		first := strings.SplitN(out, "\n", 2)[0]
		if !strings.Contains(first, c.seq) {
			t.Errorf("first line %q must carry %q", first, c.seq)
		}
	}
}

func TestDefaultOutputHidesMeasurements(t *testing.T) {
	out := plain(t, sampleFacts())

	for _, unwanted := range []string{"MEASUREMENTS", "TUNNEL EXIT", "PROBES", "198.51.100.20"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the default output must not contain %q:\n%s", unwanted, out)
		}
	}
	if !strings.Contains(out, "Run with -v") {
		t.Errorf("the default output must say where the measurements went:\n%s", out)
	}
}

// The default output must answer each question in order, so the reader can stop
// after four lines.
func TestDefaultOutputAnswersTheFourQuestions(t *testing.T) {
	out := plain(t, sampleFacts())

	for i, label := range []string{"Own DNS", "All DNS via proxy", "DNS hijacking", "DNS leakage"} {
		if !strings.Contains(out, label) {
			t.Errorf("label %d (%q) is missing:\n%s", i+1, label, out)
		}
	}
}

func TestVerboseOutputShowsMeasurements(t *testing.T) {
	out := renderText(t, sampleFacts(), Options{Verbose: true})

	for _, want := range []string{
		"MEASUREMENTS",
		"TUNNEL EXIT",
		"RESOLVERS",
		"PROBES",
		"198.51.100.20",
		"100.101.255.254",
		"AS64500",
		"hijack",
		"cleartext",
		"ipv6 leak",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detail %q is missing:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Run with -v") {
		t.Errorf("the hint to use -v must not print when -v is given:\n%s", out)
	}
}

// A run that measured nothing must say so rather than print empty sections.
func TestVerboseOutputWithNoMeasurements(t *testing.T) {
	out := renderText(t, analyze.Facts{}, Options{Verbose: true})

	for _, want := range []string{"not measured", "none found", "did not complete"} {
		if !strings.Contains(out, want) {
			t.Errorf("placeholder %q is missing:\n%s", want, out)
		}
	}
}

// A rewritten name must appear in the detail, so the reader can see which
// answer was invented.
func TestVerboseOutputListsHijackedNames(t *testing.T) {
	facts := sampleFacts()
	facts.Hijack = probe.HijackResult{
		Probed:  []string{"aaaa.example.com", "bbbb.example.net"},
		Answers: map[string][]netip.Addr{"aaaa.example.com": {addr("45.33.32.156")}},
	}
	out := renderText(t, facts, Options{Verbose: true})

	if !strings.Contains(out, "1 rewritten into addresses") {
		t.Errorf("the hijack count is missing:\n%s", out)
	}
	if strings.Contains(out, "bbbb.example.net ->") {
		t.Errorf("only the rewritten names belong in the detail:\n%s", out)
	}
}

// At most three fixes are listed, so the section stays a to-do list.
func TestFixesAreCapped(t *testing.T) {
	out := plain(t, worstCaseFacts())

	count := 0
	for _, n := range []string{"\n  ", "\n  1. ", "\n  2. ", "\n  3. ", "\n  4. "} {
		if n == "\n  " {
			continue
		}
		count += strings.Count(out, n)
	}
	if count > maxFixes {
		t.Errorf("printed %d fixes, want at most %d:\n%s", count, maxFixes, out)
	}
}

// A run with nothing to fix must say so rather than print an empty heading.
func TestNothingToFix(t *testing.T) {
	out := plain(t, controlledFacts())
	if !strings.Contains(out, "Nothing to fix.") {
		t.Errorf("output must say there is nothing to fix:\n%s", out)
	}
	if strings.Contains(out, "FIX FIRST") {
		t.Errorf("an empty list must not print a heading:\n%s", out)
	}
}

func TestLeaderAndPad(t *testing.T) {
	if got := leader("Own DNS", 21); got != "Own DNS ............." {
		t.Errorf("leader = %q", got)
	}
	if got := leader("a-very-long-label-beyond-the-column", 10); !strings.HasPrefix(got, "a-very-long-label-beyond-the-column") {
		t.Errorf("leader must not truncate, got %q", got)
	}
	if got := padLeft(6, "ab"); got != "    ab" {
		t.Errorf("padLeft = %q", got)
	}
	if got := padLeft(2, "abcd"); got != "abcd" {
		t.Errorf("padLeft must not truncate, got %q", got)
	}
}

// stripEscapes removes the CSI sequences the style adds, so the coloured output
// can be compared with the plain one.
func stripEscapes(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != 0x1b {
			sb.WriteByte(s[i])
			continue
		}
		for i < len(s) && s[i] != 'm' {
			i++
		}
	}
	return sb.String()
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func sampleFacts() analyze.Facts {
	return analyze.Facts{
		Resolvers: []analyze.ResolverView{{
			Addr:          addr("100.101.255.254"),
			Port:          53,
			Kind:          sysdns.KindOverlay,
			Reachable:     true,
			Explicit:      true,
			ServesDomains: 2,
			EchoAddr:      addr("198.51.100.20"),
			UpstreamAddr:  addr("198.51.100.21"),
		}},
		ServiceNames:     []string{"Wi-Fi"},
		ExplicitServices: 1,
		TotalServices:    3,
		PlaintextUDP:     true,
		Egress:           &probe.Egress{Addr: addr("198.51.100.20"), Site: "cloudflare.com"},
		EgressOrigin:     &probe.Origin{ASN: 64500, Country: "DE", Prefix: "198.51.100.0/24"},
		Origins:          map[string]probe.Origin{"198.51.100.20": {ASN: 64500, Country: "DE"}},
		Hijack:           probe.HijackResult{Probed: []string{"aaaa.example.com"}},
	}
}

// controlledFacts describes a machine where nothing needs fixing.
func controlledFacts() analyze.Facts {
	facts := sampleFacts()
	facts.PlaintextUDP = false
	return facts
}

// worstCaseFacts describes a machine on which nothing is controlled.
func worstCaseFacts() analyze.Facts {
	return analyze.Facts{
		Resolvers: []analyze.ResolverView{{
			Addr:      addr("203.0.113.7"),
			Port:      53,
			Kind:      sysdns.KindPublic,
			Reachable: true,
			EchoAddr:  addr("203.0.113.7"),
		}},
		Egress:       &probe.Egress{Addr: addr("198.51.100.9"), Site: "cloudflare.com"},
		EgressOrigin: &probe.Origin{ASN: 64500, Country: "DE"},
		Origins:      map[string]probe.Origin{"203.0.113.7": {ASN: 64501, Country: "FR"}},
		PlaintextUDP: true,
		PlaintextTCP: true,
		Hijack: probe.HijackResult{
			Probed:  []string{"x.example.com", "y.example.net"},
			Answers: map[string][]netip.Addr{"x.example.com": {addr("45.33.32.156")}},
		},
		TotalServices: 1,
	}
}
