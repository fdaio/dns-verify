package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/fdaio/dns-verify/internal/analyze"
	"github.com/fdaio/dns-verify/internal/probe"
	"github.com/fdaio/dns-verify/internal/sysdns"
	"github.com/fdaio/dns-verify/internal/term"
)

func staticCheck(facts analyze.Facts) checker {
	return func(context.Context) (analyze.Report, error) { return analyze.Build(facts), nil }
}

func failingCheck(err error) checker {
	return func(context.Context) (analyze.Report, error) { return analyze.Report{}, err }
}

// runMain calls the command with a canned report so the flags and the exit code
// can be checked without a network.
func runMain(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := realMain(args, &stdout, &stderr, term.Env{}, staticCheck(worstCaseFacts()), func() {})
	return code, stdout.String(), stderr.String()
}

// The default output must fit on one screen, so the verdict block cannot grow
// with the number of problems found.
func TestDefaultOutputFitsOnOneScreen(t *testing.T) {
	_, stdout, _ := runMain(t)
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) > 24 {
		t.Errorf("the default output is %d lines, want at most 24:\n%s", len(lines), stdout)
	}
}

// The score is the headline, so it must be on the first line.
func TestScoreIsOnTheFirstLine(t *testing.T) {
	_, stdout, _ := runMain(t)
	first := strings.SplitN(stdout, "\n", 2)[0]
	for _, want := range []string{"DNS VERIFY", "/10", "NOT MANAGED"} {
		if !strings.Contains(first, want) {
			t.Errorf("the first line %q must contain %q", first, want)
		}
	}
}

// A plain run is for a person reading it, so it must never fail on a score.
func TestPlainRunAlwaysSucceeds(t *testing.T) {
	if code, _, _ := runMain(t); code != 0 {
		t.Errorf("a plain run returned %d, want 0", code)
	}
}

func TestFailUnder(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"below the threshold", []string{"--fail-under", "10"}, 1},
		{"at the threshold", []string{"--fail-under", "2"}, 0},
		{"threshold off by default", []string{}, 0},
		{"above the maximum", []string{"--fail-under", "11"}, 2},
		{"negative", []string{"--fail-under", "-1"}, 2},
		{"not a number", []string{"--fail-under", "nine"}, 2},
		{"unknown flag", []string{"--nope"}, 2},
		{"stray argument", []string{"extra"}, 2},
		{"verbose runs clean", []string{"-v"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, _, _ := runMain(t, c.args...); code != c.want {
				t.Errorf("args %v returned %d, want %d", c.args, code, c.want)
			}
		})
	}
}

// A threshold that is not met must say so on stderr, not only through the code.
func TestFailUnderExplainsItself(t *testing.T) {
	_, _, stderr := runMain(t, "--fail-under", "10")
	if !strings.Contains(stderr, "score 2 is below --fail-under 10") {
		t.Errorf("stderr = %q, want the score and the threshold", stderr)
	}
}

func TestVerboseAddsMeasurements(t *testing.T) {
	_, quiet, _ := runMain(t)
	_, loud, _ := runMain(t, "-v")

	if strings.Contains(quiet, "MEASUREMENTS") {
		t.Errorf("the default output must not carry measurements:\n%s", quiet)
	}
	if !strings.Contains(loud, "MEASUREMENTS") {
		t.Errorf("-v must add the measurements:\n%s", loud)
	}
	if len(loud) <= len(quiet) {
		t.Error("-v must print more than the default")
	}
}

// A failed check must exit non-zero and say why, rather than printing a report
// that reads as a clean run.
func TestCheckFailure(t *testing.T) {
	var stdout, stderr strings.Builder
	code := realMain(nil, &stdout, &stderr, term.Env{}, failingCheck(errors.New("scutil --dns: not found")), func() {})

	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "scutil --dns: not found") {
		t.Errorf("stderr = %q, want the failure", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("nothing must be printed when the check failed, got %q", stdout.String())
	}
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

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
		Egress:        &probe.Egress{Addr: addr("198.51.100.9"), Site: "cloudflare.com"},
		EgressOrigin:  &probe.Origin{ASN: 64500, Country: "DE"},
		Origins:       map[string]probe.Origin{"203.0.113.7": {ASN: 64501, Country: "FR"}},
		PlaintextUDP:  true,
		PlaintextTCP:  true,
		TotalServices: 1,
		Hijack: probe.HijackResult{
			Probed:  []string{"x.example.com", "y.example.net"},
			Answers: map[string][]netip.Addr{"x.example.com": {addr("45.33.32.156")}},
		},
	}
}

// The progress row is erased before the report starts. Erasing afterwards would
// land on the last line of the report and blank it.
func TestProgressIsClearedBeforeTheReport(t *testing.T) {
	var stdout, stderr strings.Builder
	order := &callOrder{}

	realMain(nil, &stdout, &stderr, term.Env{},
		func(context.Context) (analyze.Report, error) {
			order.record("check")
			return analyze.Build(worstCaseFacts()), nil
		},
		func() {
			order.record("clear")
			fmt.Fprint(&stdout, "\x1b[ERASE\x1b[0m")
		})

	want := []string{"check", "clear"}
	if !order.matches(want) {
		t.Fatalf("call order = %v, want %v", order.calls, want)
	}
	erase := strings.Index(stdout.String(), "\x1b[ERASE")
	report := strings.Index(stdout.String(), "DNS VERIFY")
	if erase < 0 || report < 0 || report < erase {
		t.Errorf("the report must start after the erase, got %q", stdout.String()[:40])
	}
}

// callOrder records the sequence in which the command ran its parts.
type callOrder struct {
	calls []string
}

func (o *callOrder) record(name string) { o.calls = append(o.calls, name) }

func (o *callOrder) matches(want []string) bool {
	return slices.Equal(o.calls, want)
}
