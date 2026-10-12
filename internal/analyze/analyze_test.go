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

func TestBuildAsksTheFourQuestions(t *testing.T) {
	r := Build(Facts{})
	want := []string{
		"Do you have your own DNS service?",
		"Does all DNS go through the proxy?",
		"Is there DNS hijacking?",
		"Is there DNS leakage?",
	}
	for i, a := range answers(t, r) {
		if a.Question != want[i] {
			t.Errorf("question %d = %q, want %q", i+1, a.Question, want[i])
		}
		if a.State != StateUnknown {
			t.Errorf("question %d state = %v, want unknown when nothing was measured", i+1, a.State)
		}
	}
}

// A tunnel-local resolver that answers from the tunnel exit is the clean case:
// the machine chose the resolver, the path stays in the tunnel, nothing is
// rewritten, and no query escapes.
func TestEverythingControlled(t *testing.T) {
	r := Build(controlledFacts())
	for i, a := range answers(t, r) {
		if a.State != StateGood {
			t.Errorf("question %d = %v (%s), want good", i+1, a.State, a.Summary)
		}
	}
	if got := r.Overall(); got != "DNS is under control on this machine." {
		t.Errorf("Overall() = %q", got)
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
	headline := r.Overall()
	if !strings.Contains(headline, "not being managed") {
		t.Errorf("Overall() = %q, want the unmanaged headline", headline)
	}
	if !strings.Contains(headline, "no resolver is chosen") {
		t.Errorf("Overall() = %q, want the fallback conclusion", headline)
	}
}

// A cleartext public resolver with no encrypted profile is a warning on the
// first question, not a clean result.
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
	if !strings.Contains(first.Summary, "in the clear") {
		t.Errorf("summary should name the cleartext exposure: %q", first.Summary)
	}
	if first.Advice == "" {
		t.Error("a warning must carry advice")
	}
}

// A DoH or DoT profile satisfies the resolver question on its own.
func TestEncryptedProfileCountsAsControl(t *testing.T) {
	facts := controlledFacts()
	facts.EncryptedProfiles = []string{"cloudflare.com DoH"}
	r := Build(facts)

	first := r.Answers[0]
	if !strings.Contains(first.Summary, "encrypted profile") {
		t.Errorf("summary should report the installed profile: %q", first.Summary)
	}
}

// A tunnel-local resolver that answers from a source other than the tunnel exit
// sends queries outside the proxy. That is the leak the tool exists to find.
func TestOffTunnelResolverIsUnmanaged(t *testing.T) {
	facts := controlledFacts()
	facts.Resolvers[0].EchoAddr = addr("192.0.2.44")
	facts.PlaintextUDP = false
	r := Build(facts)

	proxy := r.Answers[1]
	if proxy.State != StateUnmanaged {
		t.Fatalf("proxy coverage = %v (%s), want unmanaged", proxy.State, proxy.Summary)
	}
	if !strings.Contains(proxy.Summary, "bypass the proxy") {
		t.Errorf("summary should say the lookups bypass: %q", proxy.Summary)
	}

	leak := r.Answers[3]
	if leak.State != StateUnmanaged {
		t.Fatalf("leakage = %v (%s), want unmanaged", leak.State, leak.Summary)
	}
	if !strings.Contains(leak.Summary, "different source") {
		t.Errorf("summary should name the outside source: %q", leak.Summary)
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

	leak := r.Answers[3]
	if leak.State != StateWarn {
		t.Fatalf("leakage = %v (%s), want warn", leak.State, leak.Summary)
	}
	if !strings.Contains(leak.Summary, "same network") {
		t.Errorf("summary should name the shared network: %q", leak.Summary)
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

// An open port 53 means a query can still leave in the clear, so the path is
// only partly covered.
func TestOpenPort53Warns(t *testing.T) {
	facts := controlledFacts()
	facts.PlaintextUDP = true
	r := Build(facts)

	proxy := r.Answers[1]
	if proxy.State != StateWarn {
		t.Fatalf("proxy coverage = %v (%s), want warn", proxy.State, proxy.Summary)
	}
	if !strings.Contains(proxy.Summary, "port 53") {
		t.Errorf("summary should name the open port: %q", proxy.Summary)
	}
}

// A rewritten answer to a name that cannot exist is hijacking.
func TestHijackedNameIsUnmanaged(t *testing.T) {
	facts := controlledFacts()
	facts.Hijack = probe.HijackResult{
		Probed: []string{"a.example.com", "b.example.net"},
		Answers: map[string][]netip.Addr{
			"a.example.com": {addr("45.33.32.156")},
		},
	}
	r := Build(facts)

	hijack := r.Answers[2]
	if hijack.State != StateUnmanaged {
		t.Fatalf("hijack = %v (%s), want unmanaged", hijack.State, hijack.Summary)
	}
	if !strings.Contains(hijack.Summary, "a.example.com") {
		t.Errorf("summary should name the rewritten label: %q", hijack.Summary)
	}
	if !strings.Contains(hijack.Summary, "1 of 2") {
		t.Errorf("summary should show how many names were rewritten: %q", hijack.Summary)
	}
}

// A probe that completed without a rewrite is a clean result.
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

	proxy := r.Answers[1]
	if proxy.State != StateWarn {
		t.Fatalf("proxy coverage = %v (%s), want warn", proxy.State, proxy.Summary)
	}
	if !strings.Contains(proxy.Summary, "2001:db8::1") {
		t.Errorf("summary should name the address: %q", proxy.Summary)
	}
}

// The resolver label must not hide the fact that a public resolver is cleartext.
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

func TestWorstAndStateLabels(t *testing.T) {
	r := Build(Facts{})
	if r.Worst() != StateUnknown {
		t.Errorf("Worst() = %v, want unknown", r.Worst())
	}
	if got := StateUnmanaged.String(); got != "unmanaged" {
		t.Errorf("State.String() = %q", got)
	}
	if got := lower(StateGood, StateWarn); got != StateWarn {
		t.Errorf("lower(good, warn) = %v, want warn", got)
	}
	if got := lower(StateGood, StateUnmanaged); got != StateUnmanaged {
		t.Errorf("lower(good, unmanaged) = %v, want unmanaged", got)
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
			ServesDomains: []string{"netbird.cloud"},
			EchoAddr:      addr("198.51.100.20"),
		}},
		SplitScopedDomains: 1,
		ExplicitServices:   1,
		TotalServices:      1,
		Egress:             &probe.Egress{Addr: addr("198.51.100.20"), Site: "cloudflare.com"},
		EgressOrigin:       &probe.Origin{ASN: 64500, Country: "DE"},
		Origins:            map[string]probe.Origin{"198.51.100.20": {ASN: 64500, Country: "DE"}},
		Hijack:             probe.HijackResult{Probed: []string{"a.example.com"}},
	}
}
