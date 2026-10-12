package analyze

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/fdaio/dns-verify/internal/probe"
	"github.com/fdaio/dns-verify/internal/sysdns"
)

func addr(s string) netip.Addr {
	return netip.MustParseAddr(s)
}

func answers(t *testing.T, r Report) []Answer {
	t.Helper()
	if len(r.Answers) != 4 {
		t.Fatalf("got %d answers, want the four questions", len(r.Answers))
	}
	return r.Answers
}

// The compact report shows the label, so the four lines must stay distinct.
func TestBuildAsksTheFourQuestions(t *testing.T) {
	want := []string{
		"Do you have your own DNS service?",
		"Does all DNS go through the proxy?",
		"Is there DNS hijacking?",
		"Is there DNS leakage?",
	}
	labels := []string{"Own DNS", "All DNS via proxy", "DNS hijacking", "DNS leakage"}

	for i, a := range answers(t, Build(Facts{})) {
		if a.Question != want[i] {
			t.Errorf("question %d = %q, want %q", i+1, a.Question, want[i])
		}
		if a.Label != labels[i] {
			t.Errorf("label %d = %q, want %q", i+1, a.Label, labels[i])
		}
		if a.State != StateUnknown {
			t.Errorf("question %d state = %v, want unknown when nothing was measured", i+1, a.State)
		}
		if a.Hint == "" {
			t.Errorf("question %d has no hint, but every line needs one", i+1)
		}
	}
}

// A machine that controls everything must score the full ten points.
func TestEverythingControlledScoresTen(t *testing.T) {
	r := Build(controlledFacts())
	for i, a := range answers(t, r) {
		if a.State != StateGood {
			t.Errorf("question %d = %v (%s), want good", i+1, a.State, a.Summary)
		}
	}
	if got := r.Score(); got != 10 {
		t.Errorf("Score() = %d, want 10", got)
	}
	if got := r.Grade(); got != "UNDER CONTROL" {
		t.Errorf("Grade() = %q, want UNDER CONTROL", got)
	}
	if got := r.NotMeasured(); got != 0 {
		t.Errorf("NotMeasured() = %d, want 0", got)
	}
}

// The fallback verdict must appear when nothing on the machine controls any of
// the four aspects.
func TestNothingManagedFallsBackToUnmanaged(t *testing.T) {
	facts := Facts{
		Resolvers: []ResolverView{{
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
			Probed: []string{"x.example.com", "y.example.net"},
			Answers: map[string][]netip.Addr{
				"x.example.com": {addr("45.33.32.156")},
			},
		},
		TotalServices: 1,
	}
	r := Build(facts)

	got := answers(t, r)
	wantState := []State{StateWarn, StateUnmanaged, StateUnmanaged, StateUnmanaged}
	for i, a := range got {
		if a.State != wantState[i] {
			t.Errorf("question %d = %v (%s), want %v", i+1, a.State, a.Summary, wantState[i])
		}
	}
	if got := r.Grade(); got != "NOT MANAGED" {
		t.Errorf("Grade() = %q, want NOT MANAGED", got)
	}
	// warn=1.5, the other three earn nothing.
	if got := r.Score(); got != 2 {
		t.Errorf("Score() = %d, want 2", got)
	}
}

// A warning costs one point, which is the difference between a full and a
// partial result.
func TestWarnLosesOnePoint(t *testing.T) {
	facts := controlledFacts()
	facts.PlaintextUDP = true
	r := Build(facts)

	if got := r.Score(); got != 9 {
		t.Errorf("Score() = %d, want 9", got)
	}
	if got := r.Grade(); got != "PARTLY MANAGED" {
		t.Errorf("Grade() = %q, want PARTLY MANAGED", got)
	}
}

// An unmeasured question must not be scored as safe.
func TestUnmeasuredQuestionScoresNothing(t *testing.T) {
	facts := controlledFacts()
	facts.Egress = nil
	r := Build(facts)

	if got := r.Score(); got != 8 {
		t.Errorf("Score() = %d, want 8 with one question unmeasured", got)
	}
	if got := r.NotMeasured(); got != 1 {
		t.Errorf("NotMeasured() = %d, want 1", got)
	}
	if got := r.Grade(); got != "INCONCLUSIVE" {
		t.Errorf("Grade() = %q, want INCONCLUSIVE", got)
	}
}

// A cleartext public resolver with no encrypted profile is a warning.
func TestPublicCleartextResolverWarns(t *testing.T) {
	facts := controlledFacts()
	facts.Resolvers = append(facts.Resolvers, ResolverView{
		Addr:      addr("8.8.8.8"),
		Port:      53,
		Kind:      sysdns.KindPublic,
		Reachable: true,
	})
	r := Build(facts)

	first := r.Answers[0]
	if first.State != StateWarn {
		t.Fatalf("own resolver = %v (%s), want warn", first.State, first.Summary)
	}
	if first.Hint != "a public resolver answers in the clear" {
		t.Errorf("hint = %q, want the short form of the summary", first.Hint)
	}
	if first.Fix == nil {
		t.Fatal("a warning must carry a fix")
	}
}

// A DoH or DoT profile satisfies the resolver question on its own.
func TestEncryptedProfileCountsAsControl(t *testing.T) {
	facts := controlledFacts()
	facts.EncryptedProfiles = []string{"cloudflare.com DoH"}
	r := Build(facts)

	if !strings.Contains(r.Answers[0].Summary, "encrypted profile") {
		t.Errorf("summary should report the installed profile: %q", r.Answers[0].Summary)
	}
}

// The fix may only name a service and an address when both are known. A command
// with a placeholder in it is easier to run wrong than to read.
func TestFixCommandOnlyWhenFullyKnown(t *testing.T) {
	facts := controlledFacts()
	facts.Resolvers = append(facts.Resolvers, ResolverView{
		Addr:      addr("8.8.8.8"),
		Port:      53,
		Kind:      sysdns.KindPublic,
		Reachable: true,
	})

	facts.ServiceNames = []string{"Wi-Fi"}
	r := Build(facts)
	fix := r.Answers[0].Fix
	if fix == nil {
		t.Fatal("a warning must carry a fix")
	}
	want := `networksetup -setdnsservers "Wi-Fi" 100.101.255.254`
	if fix.Command != want {
		t.Errorf("command = %q, want %q", fix.Command, want)
	}

	// With several services the tool cannot know which one to write.
	facts.ServiceNames = []string{"Wi-Fi", "iPhone USB"}
	fix = Build(facts).Answers[0].Fix
	if fix == nil || fix.Command != "" {
		t.Errorf("an ambiguous service must produce no command, got %+v", fix)
	}
	if fix == nil || fix.Text == "" {
		t.Error("the fix must still say what to do in words")
	}
}

// A tunnel-local resolver that answers from a source other than the tunnel exit
// sends queries outside the proxy.
func TestOffTunnelResolverIsUnmanaged(t *testing.T) {
	facts := controlledFacts()
	facts.Resolvers[0].EchoAddr = addr("192.0.2.44")
	facts.PlaintextUDP = false
	r := Build(facts)

	proxy := r.Answers[1]
	if proxy.State != StateUnmanaged {
		t.Fatalf("proxy coverage = %v (%s), want unmanaged", proxy.State, proxy.Summary)
	}
	if !strings.Contains(proxy.Hint, "outside the tunnel exit") {
		t.Errorf("hint should name the outside source: %q", proxy.Hint)
	}
	if r.Answers[3].State != StateUnmanaged {
		t.Errorf("leakage = %v, want unmanaged", r.Answers[3].State)
	}
}

// A resolver in the same network as the exit is not an outside leak, but its
// queries are still readable there.
func TestResolverInExitNetworkWarnsRatherThanFails(t *testing.T) {
	facts := controlledFacts()
	facts.Resolvers[0].EchoAddr = addr("192.0.2.44")
	facts.PlaintextUDP = false
	facts.EgressOrigin = &probe.Origin{ASN: 64500, Country: "DE"}
	facts.Origins = map[string]probe.Origin{"192.0.2.44": {ASN: 64500, Country: "DE"}}
	r := Build(facts)

	if got := r.Answers[3].State; got != StateWarn {
		t.Fatalf("leakage = %v (%s), want warn", got, r.Answers[3].Summary)
	}
}

// A resolver that cannot report its source address must not be counted as clean.
func TestUnmeasurableResolverIsNamed(t *testing.T) {
	facts := controlledFacts()
	facts.Resolvers = append(facts.Resolvers, ResolverView{
		Addr:      addr("223.5.5.5"),
		Port:      53,
		Kind:      sysdns.KindPublic,
		Reachable: true,
	})
	r := Build(facts)

	leak := r.Answers[3]
	if !strings.Contains(leak.Summary, "could not be measured") {
		t.Errorf("summary should name the resolver it could not judge: %q", leak.Summary)
	}
	if !strings.Contains(leak.Summary, "1 of 2") {
		t.Errorf("summary should count only the resolvers it measured: %q", leak.Summary)
	}
}

// An open port 53 means a query can still leave in the clear.
func TestOpenPort53Warns(t *testing.T) {
	facts := controlledFacts()
	facts.PlaintextUDP = true
	r := Build(facts)

	if got := r.Answers[1].State; got != StateWarn {
		t.Fatalf("proxy coverage = %v, want warn", got)
	}
	if r.Answers[1].Fix == nil {
		t.Fatal("an open port must carry a fix")
	}
}

// A rewritten answer to a name that cannot exist is hijacking.
func TestHijackedNameIsUnmanaged(t *testing.T) {
	facts := controlledFacts()
	facts.Hijack = probe.HijackResult{
		Probed:  []string{"a.example.com", "b.example.net"},
		Answers: map[string][]netip.Addr{"a.example.com": {addr("45.33.32.156")}},
	}
	r := Build(facts)

	hijack := r.Answers[2]
	if hijack.State != StateUnmanaged {
		t.Fatalf("hijack = %v (%s), want unmanaged", hijack.State, hijack.Summary)
	}
	if hijack.Hint != "1 of 2 names rewritten into addresses" {
		t.Errorf("hint = %q", hijack.Hint)
	}
	if !strings.Contains(hijack.Summary, "a.example.com") {
		t.Errorf("summary should name the rewritten label: %q", hijack.Summary)
	}
}

func TestNoHijackIsGood(t *testing.T) {
	r := Build(controlledFacts())
	hijack := r.Answers[2]
	if hijack.State != StateGood {
		t.Fatalf("hijack = %v (%s), want good", hijack.State, hijack.Summary)
	}
	if strings.Contains(hijack.Summary, "->") {
		t.Errorf("a clean result must not list rewritten names: %q", hijack.Summary)
	}
}

// An IPv6 address outside the tunnel gives a lookup a second way out.
func TestIPv6BypassDowngradesCoverage(t *testing.T) {
	facts := controlledFacts()
	facts.IPv6Bypass = []string{"2001:db8::1 (en0)"}
	r := Build(facts)

	if got := r.Answers[1].State; got != StateWarn {
		t.Fatalf("proxy coverage = %v, want warn", got)
	}
	if !strings.Contains(r.Answers[1].Summary, "2001:db8::1") {
		t.Errorf("summary should name the address: %q", r.Answers[1].Summary)
	}
}

// The fixes are a to-do list, so the urgent one comes first and a question that
// could not be measured never hides a real finding.
func TestFixesAreOrderedByUrgency(t *testing.T) {
	facts := controlledFacts()
	facts.Hijack = probe.HijackResult{
		Probed:  []string{"a.example.com"},
		Answers: map[string][]netip.Addr{"a.example.com": {addr("45.33.32.156")}},
	}
	facts.Resolvers[0].EchoAddr = addr("192.0.2.44")
	facts.PlaintextUDP = true
	facts.Egress = &probe.Egress{Addr: addr("198.51.100.20"), Site: "cloudflare.com"}

	fixes := Build(facts).Fixes()
	if len(fixes) != 3 {
		t.Fatalf("got %d fixes, want 3", len(fixes))
	}
	for i := 1; i < len(fixes); i++ {
		if fixes[i].Severity > fixes[i-1].Severity {
			t.Errorf("fix %d (%v) outranks fix %d (%v)", i, fixes[i].Severity, i-1, fixes[i-1].Severity)
		}
	}
}

func TestResolverLabel(t *testing.T) {
	cases := []struct {
		view ResolverView
		want string
	}{
		{ResolverView{Addr: addr("100.101.255.254"), Kind: sysdns.KindOverlay}, "100.101.255.254 (overlay)"},
		{ResolverView{Addr: addr("1.1.1.1"), Kind: sysdns.KindPublic, Port: 53}, "1.1.1.1 (public) cleartext :53"},
		{ResolverView{Addr: addr("1.1.1.1"), Kind: sysdns.KindPublic, Port: 443}, "1.1.1.1 (public) encrypted"},
		{ResolverView{Addr: addr("198.18.0.2"), Kind: sysdns.KindFakeIP, FakeIP: true}, "198.18.0.2 (fake-ip) hands out fake addresses"},
	}
	for _, c := range cases {
		if got := resolverLabel(c.view); got != c.want {
			t.Errorf("resolverLabel = %q, want %q", got, c.want)
		}
	}
}

func TestStateLabels(t *testing.T) {
	cases := map[State]string{
		StateGood:      "good",
		StateWarn:      "warn",
		StateUnmanaged: "unmanaged",
		StateUnknown:   "unknown",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestJoinAnd(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"one"}, "one"},
		{[]string{"one", "two"}, "one, and two"},
		{[]string{"one", "two", "three"}, "one, two, and three"},
	}
	for _, c := range cases {
		if got := joinAnd(c.in); got != c.want {
			t.Errorf("joinAnd(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// controlledFacts describes a machine where a mesh VPN owns the resolver and
// every path stays inside the tunnel.
func controlledFacts() Facts {
	return Facts{
		Resolvers: []ResolverView{{
			Addr:          addr("100.101.255.254"),
			Port:          53,
			Kind:          sysdns.KindOverlay,
			Reachable:     true,
			Explicit:      true,
			ServesDomains: 1,
			EchoAddr:      addr("198.51.100.20"),
		}},
		ServiceNames:     []string{"Wi-Fi"},
		ExplicitServices: 1,
		TotalServices:    1,
		Egress:           &probe.Egress{Addr: addr("198.51.100.20"), Site: "cloudflare.com"},
		EgressOrigin:     &probe.Origin{ASN: 64500, Country: "DE"},
		Origins:          map[string]probe.Origin{"198.51.100.20": {ASN: 64500, Country: "DE"}},
		Hijack:           probe.HijackResult{Probed: []string{"a.example.com"}},
	}
}
