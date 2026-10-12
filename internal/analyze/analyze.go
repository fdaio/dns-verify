// Package analyze turns raw DNS measurements into the four answers the report
// exists to give. Every rule is a pure function of the measurements, so the
// reasoning can be tested without a network.
package analyze

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/fdaio/dns-verify/internal/probe"
	"github.com/fdaio/dns-verify/internal/sysdns"
)

// State is the outcome of a single question, ordered from worst to best so that
// two results can be reduced with a minimum.
type State int

const (
	// StateUnknown means the measurement did not complete.
	StateUnknown State = iota
	// StateUnmanaged means nothing controls this aspect.
	StateUnmanaged
	// StateWarn means a control exists but does not cover everything.
	StateWarn
	// StateGood means the control holds.
	StateGood
)

// String returns the short label used in the report.
func (s State) String() string {
	switch s {
	case StateGood:
		return "good"
	case StateWarn:
		return "warn"
	case StateUnmanaged:
		return "unmanaged"
	default:
		return "unknown"
	}
}

// ResolverView is one resolver that serves lookups on this machine.
type ResolverView struct {
	// Addr is the nameserver address.
	Addr netip.Addr
	// Port is the resolver port. Zero means the default port.
	Port uint16
	// Kind classifies who operates the resolver.
	Kind sysdns.Kind
	// Flags holds the scutil flags of the resolver entry.
	Flags []string
	// Reachable reports the macOS reachability bit.
	Reachable bool
	// FakeIP marks a resolver that hands out fake addresses.
	FakeIP bool
	// Explicit marks a server set on a network service by hand. A resolver the
	// network hands out is not a choice.
	Explicit bool
	// ServesDomains lists the split-DNS domains routed to this resolver.
	ServesDomains []string
	// EchoAddr is the source address the resolver reported. It shows which path
	// the resolver reaches the internet by, which is the path every lookup
	// through it takes.
	EchoAddr netip.Addr
	// EchoErr records why the echo lookup failed.
	EchoErr error
	// UpstreamAddr is the resolver that answered from the far side of a
	// forwarder. It is unset when the resolver answers for itself.
	UpstreamAddr netip.Addr
}

// Encrypted reports whether the resolver is reached over an encrypted port or
// carries an encryption flag in the system configuration.
func (r ResolverView) Encrypted() bool {
	if sysdns.IsEncryptedPort(r.Port) {
		return true
	}
	for _, flag := range r.Flags {
		if sysdns.IsEncryptedFlag(flag) {
			return true
		}
	}
	return false
}

// Facts is everything the analysis reads.
type Facts struct {
	// Resolvers are the resolvers that serve ordinary lookups.
	Resolvers []ResolverView
	// SplitScopedDomains is the number of domains routed to a dedicated resolver.
	SplitScopedDomains int
	// ExplicitServices is the number of network services with a hand-set server.
	ExplicitServices int
	// TotalServices is the number of enabled network services.
	TotalServices int
	// EncryptedProfiles lists the encrypted resolver profiles found in
	// /etc/resolver.
	EncryptedProfiles []string
	// PlaintextUDP marks cleartext DNS that completes over UDP.
	PlaintextUDP bool
	// PlaintextTCP marks cleartext DNS that completes over TCP.
	PlaintextTCP bool
	// Hijack is the result of the reserved-name probe.
	Hijack probe.HijackResult
	// HijackErr records why the probe did not complete.
	HijackErr error
	// FakeIPTarget is the name used to test for fake addresses.
	FakeIPTarget string
	// IPv6Bypass lists IPv6 addresses that the tunnel does not cover.
	IPv6Bypass []string
	// Egress is the source address of ordinary traffic, when measured.
	Egress *probe.Egress
	// EgressOrigin is the network the egress address belongs to.
	EgressOrigin *probe.Origin
	// Origins maps an observed source address to the network it belongs to.
	Origins map[string]probe.Origin
}

// Answer is one of the four questions with its verdict and supporting facts.
type Answer struct {
	// Question is the question being answered.
	Question string
	// State is the verdict.
	State State
	// Summary is the one-line conclusion.
	Summary string
	// Advice is the single next step, when one applies.
	Advice string
}

// Report is the full result of a run.
type Report struct {
	// Answers holds the four questions in report order.
	Answers []Answer
	// Facts is the measurement set the answers came from.
	Facts Facts
}

// Worst returns the least reassuring state in the report.
func (r Report) Worst() State {
	worst := StateGood
	for _, a := range r.Answers {
		if a.State < worst {
			worst = a.State
		}
	}
	return worst
}

// Overall returns the one-line headline of the run.
func (r Report) Overall() string {
	var good, warn, unmanaged, unknown int
	for _, a := range r.Answers {
		switch a.State {
		case StateGood:
			good++
		case StateWarn:
			warn++
		case StateUnmanaged:
			unmanaged++
		default:
			unknown++
		}
	}

	total := len(r.Answers)
	switch {
	case total == 0:
		return "Nothing was measured."
	case good == total:
		return "DNS is under control on this machine."
	case unknown == total:
		return "Not enough was reachable to judge this machine."
	case unmanaged+warn == total-unknown:
		return "DNS is not being managed on this machine: no resolver is chosen, " +
			"the path is not covered, and the answers are not checked."
	default:
		return fmt.Sprintf("DNS is partly managed: %d of %d checks hold, %d need attention.",
			good, total, total-good-unknown)
	}
}

// Build produces the four answers from the measurements.
func Build(f Facts) Report {
	return Report{
		Answers: []Answer{
			answerOwnResolver(f),
			answerProxyCoverage(f),
			answerHijack(f),
			answerLeak(f),
		},
		Facts: f,
	}
}

// answerOwnResolver reports which resolver this machine resolves through.
func answerOwnResolver(f Facts) Answer {
	const question = "Do you have your own DNS service?"

	effective := reachable(f.Resolvers)
	if len(effective) == 0 {
		return Answer{
			Question: question,
			State:    StateUnknown,
			Summary:  "No reachable resolver is configured, so nothing was measured.",
			Advice:   "Restore the network connection, then run the check again.",
		}
	}

	var public []string
	for _, r := range effective {
		if r.Kind == sysdns.KindPublic && !r.Encrypted() {
			public = append(public, resolverLabel(r))
		}
	}

	state := StateGood
	advice := ""
	summary := "Yes. Resolution runs through " + joinLabels(effective) + "."
	if len(public) > 0 {
		state = StateWarn
		summary = "Partly. Resolution runs through " + joinLabels(effective) +
			". A public resolver answers in the clear for part of the namespace."
		advice = "Point every network service at the resolver your tunnel provides."
	}
	if f.SplitScopedDomains > 0 {
		summary += fmt.Sprintf(" %d domains are routed to a dedicated resolver.",
			f.SplitScopedDomains)
	}
	if f.TotalServices > 0 && f.ExplicitServices == 0 {
		summary += " No service has a hand-set server, so the resolver was not chosen here."
	}
	if len(f.EncryptedProfiles) > 0 {
		summary += fmt.Sprintf(" An encrypted profile is configured in %s.",
			sysdns.ResolverDir+" ("+strings.Join(f.EncryptedProfiles, ", ")+")")
	}

	return Answer{Question: question, State: state, Summary: summary, Advice: advice}
}

// answerProxyCoverage reports whether every lookup leaves through the tunnel.
func answerProxyCoverage(f Facts) Answer {
	const question = "Does all DNS go through the proxy?"

	effective := reachable(f.Resolvers)
	if len(effective) == 0 {
		return Answer{
			Question: question,
			State:    StateUnknown,
			Summary:  "No reachable resolver is configured, so nothing was measured.",
			Advice:   "Restore the network connection, then run the check again.",
		}
	}

	var offTunnel []string
	for _, r := range effective {
		// The source address the resolver reports is the fact, whatever kind of
		// resolver it is. A resolver that answers from somewhere other than the
		// tunnel exit sends the query outside the tunnel.
		if f.Egress == nil || !r.EchoAddr.IsValid() {
			continue
		}
		if r.EchoAddr != f.Egress.Addr {
			offTunnel = append(offTunnel, resolverLabel(r))
		}
	}

	state := StateGood
	advice := ""
	var summary string
	switch {
	case len(offTunnel) > 0:
		state = StateUnmanaged
		summary = "No. " + joinAnd(offTunnel) +
			" answers from outside the tunnel exit, so lookups bypass the proxy."
		advice = "Send this resolver through the tunnel, or remove it from the service."
	default:
		summary = "Yes. Lookups leave through " + joinLabels(effective) +
			", which answers from the tunnel exit."
		if f.PlaintextUDP {
			state = StateWarn
			summary += " Cleartext DNS still completes to a public resolver on port 53."
			advice = "Block outbound port 53 so only the tunnel resolver stays reachable."
		}
	}
	if len(f.IPv6Bypass) > 0 {
		state = lower(state, StateWarn)
		summary += fmt.Sprintf(" An IPv6 address is active outside the tunnel (%s), "+
			"so a v6 path can bypass it.", strings.Join(f.IPv6Bypass, ", "))
		advice = "Route IPv6 through the tunnel, or turn it off for that interface."
	}

	return Answer{Question: question, State: state, Summary: summary, Advice: advice}
}

// answerHijack reports whether unknown names were rewritten into addresses.
func answerHijack(f Facts) Answer {
	const question = "Is there DNS hijacking?"

	if len(f.Hijack.Probed) == 0 {
		return Answer{
			Question: question,
			State:    StateUnknown,
			Summary:  "The reserved-name probe did not complete, so this was not measured.",
			Advice:   "Run the check again on a network with working resolution.",
		}
	}
	if !f.Hijack.Hijacked() {
		return Answer{
			Question: question,
			State:    StateGood,
			Summary: fmt.Sprintf("None found. %d names that cannot exist all came back without an address.",
				len(f.Hijack.Probed)),
		}
	}

	labels := make([]string, 0, len(f.Hijack.Answers))
	for label, addrs := range f.Hijack.Answers {
		labels = append(labels, fmt.Sprintf("%s -> %s", label, joinAddrs(addrs)))
	}
	sort.Strings(labels)
	return Answer{
		Question: question,
		State:    StateUnmanaged,
		Summary: fmt.Sprintf("Yes. %d of %d names that cannot exist were rewritten into addresses: %s.",
			len(f.Hijack.Answers), len(f.Hijack.Probed), strings.Join(labels, "; ")),
		Advice: "Move to a resolver you trust, or point the tunnel at one.",
	}
}

// answerLeak reports whether the names are resolved by someone outside the tunnel.
func answerLeak(f Facts) Answer {
	const question = "Is there DNS leakage?"

	if f.Egress == nil {
		return Answer{
			Question: question,
			State:    StateUnknown,
			Summary:  "The tunnel exit could not be measured, so there was nothing to compare against.",
			Advice:   "Restore outbound HTTPS, then run the check again.",
		}
	}

	var leaked, unmeasured []resolverMatch
	checked := 0
	for _, r := range f.Resolvers {
		if !r.Reachable {
			continue
		}
		m := resolverMatch{view: r, origin: f.Origins[r.EchoAddr.String()]}
		if !r.EchoAddr.IsValid() {
			unmeasured = append(unmeasured, m)
			continue
		}
		checked++
		if r.EchoAddr != f.Egress.Addr {
			leaked = append(leaked, m)
		}
	}
	if checked == 0 {
		return Answer{
			Question: question,
			State:    StateUnknown,
			Summary:  "No resolver reported its source address, so leakage was not measured.",
			Advice:   "Run the check again on a network with working resolution.",
		}
	}

	exit := f.Egress.Addr.String()
	if f.EgressOrigin != nil {
		exit += fmt.Sprintf(" (%s %s)", f.EgressOrigin, f.EgressOrigin.Country)
	}
	// A resolver that does not echo its source address cannot be cleared or
	// blamed, so it is named rather than counted as clean.
	unmeasuredNote := ""
	if len(unmeasured) > 0 {
		labels := make([]string, 0, len(unmeasured))
		for _, m := range unmeasured {
			labels = append(labels, resolverLabel(m.view))
		}
		unmeasuredNote = fmt.Sprintf(" The path of %s could not be measured.",
			joinAnd(labels))
	}

	if len(leaked) == 0 {
		return Answer{
			Question: question,
			State:    StateGood,
			Summary: fmt.Sprintf("None found. Every resolver that reported its source address (%d of %d) "+
				"answers from the tunnel exit %s.%s", checked, checked+len(unmeasured), exit, unmeasuredNote),
		}
	}

	// A resolver that answers from the same network as the exit belongs to the
	// tunnel operator. Queries then stay inside that network but stay readable
	// there, which is a weaker failure than an unknown third party.
	sameNetwork := 0
	parts := make([]string, 0, len(leaked))
	for _, m := range leaked {
		parts = append(parts, m.String())
		if f.EgressOrigin != nil && m.origin.ASN == f.EgressOrigin.ASN && m.origin.ASN != 0 {
			sameNetwork++
		}
	}

	if sameNetwork == len(leaked) {
		return Answer{
			Question: question,
			State:    StateWarn,
			Summary: fmt.Sprintf("Not outside the tunnel, but not protected. Traffic exits at %s and the resolvers "+
				"answer from the same network in the clear: %s.%s", exit, joinAnd(parts),
				unmeasuredNote),
			Advice: "Encrypt the resolver with DoH or DoT so the network operator cannot read queries.",
		}
	}
	return Answer{
		Question: question,
		State:    StateUnmanaged,
		Summary: fmt.Sprintf("Yes. Traffic exits at %s, but these resolvers answer from a different source: %s.%s",
			exit, joinAnd(parts), unmeasuredNote),
		Advice: "Route these resolvers through the tunnel so the exit and the resolver agree.",
	}
}

// resolverMatch pairs a resolver with the network its answers come from.
type resolverMatch struct {
	view   ResolverView
	origin probe.Origin
}

func (m resolverMatch) String() string {
	if m.origin.ASN == 0 {
		return fmt.Sprintf("%s via %s", resolverLabel(m.view), m.view.EchoAddr)
	}
	return fmt.Sprintf("%s via %s %s", resolverLabel(m.view), m.view.EchoAddr, m.origin)
}

func reachable(in []ResolverView) []ResolverView {
	out := make([]ResolverView, 0, len(in))
	for _, r := range in {
		if r.Reachable {
			out = append(out, r)
		}
	}
	return out
}

func joinLabels(in []ResolverView) string {
	parts := make([]string, 0, len(in))
	for _, r := range in {
		parts = append(parts, resolverLabel(r))
	}
	return joinAnd(parts)
}

// joinAnd renders a list the way a sentence reads it, without repeating the
// conjunction for every element.
func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + ", and " + parts[len(parts)-1]
	}
}

// resolverLabel renders a resolver with the fact that matters for it.
func resolverLabel(r ResolverView) string {
	label := sysdns.DescribeServer(r.Addr)
	switch {
	case r.FakeIP:
		label += " hands out fake addresses"
	case r.Encrypted():
		label += " encrypted"
	case r.Kind == sysdns.KindPublic:
		label += " cleartext :53"
	}
	return label
}

func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

// lower returns the worse of two states.
func lower(a, b State) State {
	if a < b {
		return a
	}
	return b
}
