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

func renderText(t *testing.T, facts analyze.Facts) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Report(&buf, analyze.Build(facts)); err != nil {
		t.Fatalf("Report: %v", err)
	}
	return buf.String()
}

// The report must answer each question in order, so the reader can stop at the
// summary and read the details only when a line needs explaining.
func TestReportAnswersTheFourQuestions(t *testing.T) {
	out := renderText(t, sampleFacts())

	for i, question := range []string{
		"Do you have your own DNS service?",
		"Does all DNS go through the proxy?",
		"Is there DNS hijacking?",
		"Is there DNS leakage?",
	} {
		if !strings.Contains(out, question) {
			t.Errorf("question %d (%q) is missing from the report", i+1, question)
		}
	}
	if !strings.Contains(out, "Overall") {
		t.Error("the report must carry an overall verdict")
	}
}

func TestReportShowsTheMeasurements(t *testing.T) {
	out := renderText(t, sampleFacts())

	for _, want := range []string{
		"100.101.255.254",
		"198.51.100.20",
		"AS64500",
		"cleartext UDP",
		"cleartext TCP",
		"fake-ip",
		"IPv6 outside the tunnel",
		"Hijack probe",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detail %q is missing from the report", want)
		}
	}
}

// A run that measured nothing must say so rather than print empty sections.
func TestReportWithNoMeasurements(t *testing.T) {
	out := renderText(t, analyze.Facts{})

	for _, want := range []string{"none found", "not measured", "did not complete"} {
		if !strings.Contains(out, want) {
			t.Errorf("placeholder %q is missing from the report", want)
		}
	}
}

// A rewritten name must appear in the detail section, so the reader can see
// which answer was invented.
func TestReportListsHijackedNames(t *testing.T) {
	facts := sampleFacts()
	facts.Hijack = probe.HijackResult{
		Probed: []string{"aaaa.example.com", "bbbb.example.net"},
		Answers: map[string][]netip.Addr{
			"aaaa.example.com": {netip.MustParseAddr("45.33.32.156")},
		},
	}
	out := renderText(t, sampleFactsWithHijack(facts))

	if !strings.Contains(out, "aaaa.example.com -> 45.33.32.156") {
		t.Errorf("the rewritten name is missing from the report:\n%s", out)
	}
	if !strings.Contains(out, "2 unresolvable names probed, 1 rewritten") {
		t.Errorf("the hijack counts are missing from the report:\n%s", out)
	}
}

func TestPadAlignsVerdicts(t *testing.T) {
	if got := pad("good"); got != "good     " {
		t.Errorf("pad(good) = %q", got)
	}
	if got := pad("unmanaged"); got != "unmanaged" {
		t.Errorf("pad(unmanaged) = %q", got)
	}
}

func sampleFacts() analyze.Facts {
	return analyze.Facts{
		Resolvers: []analyze.ResolverView{{
			Addr:          netip.MustParseAddr("100.101.255.254"),
			Port:          53,
			Kind:          sysdns.KindOverlay,
			Reachable:     true,
			Explicit:      true,
			ServesDomains: []string{"netbird.cloud", "github.com"},
			EchoAddr:      netip.MustParseAddr("198.51.100.20"),
			UpstreamAddr:  netip.MustParseAddr("198.51.100.21"),
		}},
		SplitScopedDomains: 2,
		ExplicitServices:   1,
		TotalServices:      3,
		PlaintextUDP:       true,
		PlaintextTCP:       false,
		Egress:             &probe.Egress{Addr: netip.MustParseAddr("198.51.100.20"), Site: "cloudflare.com"},
		EgressOrigin:       &probe.Origin{ASN: 64500, Country: "DE", Prefix: "198.51.100.0/24"},
		Origins:            map[string]probe.Origin{"198.51.100.20": {ASN: 64500, Country: "DE"}},
		Hijack:             probe.HijackResult{Probed: []string{"aaaa.example.com"}},
	}
}

func sampleFactsWithHijack(facts analyze.Facts) analyze.Facts {
	return facts
}
