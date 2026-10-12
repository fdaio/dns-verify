package render

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/fdaio/dns-verify/internal/analyze"
	"github.com/fdaio/dns-verify/internal/probe"
	"github.com/fdaio/dns-verify/internal/sysdns"
)

func renderText(t *testing.T, facts analyze.Facts, verbose bool) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Report(&buf, analyze.Build(facts), verbose); err != nil {
		t.Fatalf("Report: %v", err)
	}
	return buf.String()
}

// The default output is meant to be read in one look, so it must stay short.
func TestDefaultOutputIsShort(t *testing.T) {
	out := renderText(t, worstCaseFacts(), false)

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

func TestDefaultOutputHidesMeasurements(t *testing.T) {
	out := renderText(t, sampleFacts(), false)

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
	out := renderText(t, sampleFacts(), false)

	for i, label := range []string{"Own DNS", "All DNS via proxy", "DNS hijacking", "DNS leakage"} {
		if !strings.Contains(out, label) {
			t.Errorf("label %d (%q) is missing:\n%s", i+1, label, out)
		}
	}
	if !strings.Contains(out, "Own DNS ") && !strings.Contains(out, "Own DNS.") {
		t.Errorf("the labels must line up with dot leaders:\n%s", out)
	}
}

func TestVerboseOutputShowsMeasurements(t *testing.T) {
	out := renderText(t, sampleFacts(), true)

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
	out := renderText(t, analyze.Facts{}, true)

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
	out := renderText(t, facts, true)

	if !strings.Contains(out, "1 rewritten into addresses") {
		t.Errorf("the hijack count is missing:\n%s", out)
	}
	if strings.Contains(out, "bbbb.example.net ->") {
		t.Errorf("only the rewritten names belong in the detail:\n%s", out)
	}
}

// At most three fixes are listed, so the section stays a to-do list.
func TestFixesAreCapped(t *testing.T) {
	out := renderText(t, worstCaseFacts(), false)

	fixes := strings.Count(out, "\n  1. ")
	fixes += strings.Count(out, "\n  2. ")
	fixes += strings.Count(out, "\n  3. ")
	fixes += strings.Count(out, "\n  4. ")
	if fixes > maxFixes {
		t.Errorf("printed %d fixes, want at most %d:\n%s", fixes, maxFixes, out)
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
