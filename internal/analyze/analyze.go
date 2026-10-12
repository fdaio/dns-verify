// Package analyze turns raw DNS measurements into the answers the report gives.
// Every rule is a pure function of the measurements, so the reasoning can be
// tested without a network.
package analyze

import (
	"fmt"
	"math"
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

// pointsPerQuestion spreads the ten point score over the four questions.
const pointsPerQuestion = 2.5

// pointsFor is the share of one question that a state earns. A question that
// could not be measured earns nothing, because an unmeasured question has not
// been shown to be safe.
func pointsFor(s State) float64 {
	switch s {
	case StateGood:
		return pointsPerQuestion
	case StateWarn:
		return 1.5
	default:
		return 0
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
	// ServesDomains counts the split-DNS domains routed to this resolver.
	ServesDomains int
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

// Encrypted reports whether the resolver is reached over DoH or DoT. The answer
// is derived rather than stored, so the label and the verdict cannot disagree.
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
	// ServiceNames lists the enabled network services by name.
	ServiceNames []string
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
	// IPv6Bypass lists IPv6 addresses that the tunnel does not cover.
	IPv6Bypass []string
	// Egress is the source address of ordinary traffic, when measured.
	Egress *probe.Egress
	// EgressOrigin is the network the egress address belongs to.
	EgressOrigin *probe.Origin
	// Origins maps an observed source address to the network it belongs to.
	Origins map[string]probe.Origin
}

// Fix is one action that would improve the score.
type Fix struct {
	// Severity orders the fixes. A lower value is more urgent.
	Severity State
	// Text says what to do.
	Text string
	// Command is a command that performs the fix. It is set only when the tool
	// can name the exact service and the exact address to write, because a
	// command with a placeholder in it is easier to run wrong than to read.
	Command string
}

// Answer is one of the four questions with its verdict and its consequence.
type Answer struct {
	// Label is the short name shown in the report.
	Label string
	// Question is the full question, shown only in the detailed output.
	Question string
	// State is the verdict.
	State State
	// Hint is the one-line conclusion.
	Hint string
	// Summary is the full conclusion, shown only in the detailed output.
	Summary string
	// Fix is the action that would improve this answer, if one applies.
	Fix *Fix
}

// Report is the full result of a run.
type Report struct {
	// Answers holds the four questions in report order.
	Answers []Answer
	// Facts is the measurement set the answers came from.
	Facts Facts
}

// Score is the ten point total for the run.
func (r Report) Score() int {
	total := 0.0
	for _, a := range r.Answers {
		total += pointsFor(a.State)
	}
	return int(math.Round(total))
}

// MaxScore is the score of a run in which every question is good.
const MaxScore = 10

// NotMeasured counts the questions that could not be measured.
func (r Report) NotMeasured() int {
	n := 0
	for _, a := range r.Answers {
		if a.State == StateUnknown {
			n++
		}
	}
	return n
}

// Grade is the one-word headline of a run.
type Grade int

const (
	// GradeUnknown means the run could not measure the machine.
	GradeUnknown Grade = iota
	// GradeGood means every question is under control.
	GradeGood
	// GradePartial means something is under control and something is not.
	GradePartial
	// GradePoor means nothing is under control.
	GradePoor
)

// String returns the headline as it appears in the report.
func (g Grade) String() string {
	switch g {
	case GradeGood:
		return "UNDER CONTROL"
	case GradePartial:
		return "PARTLY MANAGED"
	case GradePoor:
		return "NOT MANAGED"
	default:
		return "INCONCLUSIVE"
	}
}

// Grade is the one-word headline of the run.
func (r Report) Grade() Grade {
	switch r.Worst() {
	case StateGood:
		return GradeGood
	case StateWarn:
		return GradePartial
	case StateUnmanaged:
		return GradePoor
	default:
		return GradeUnknown
	}
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

// Fixes returns the actions worth taking, most urgent first. A question that
// could not be measured is not a defect, so it ranks behind a real finding.
func (r Report) Fixes() []Fix {
	var out []Fix
	for _, a := range r.Answers {
		if a.Fix == nil {
			continue
		}
		out = append(out, *a.Fix)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity < out[j].Severity })
	return out
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

func unknownAnswer(label, question string, hint, fix string) Answer {
	return Answer{
		Label:    label,
		Question: question,
		State:    StateUnknown,
		Hint:     hint,
		Summary:  hint,
		Fix:      &Fix{Severity: StateUnknown, Text: fix},
	}
}

// answerOwnResolver reports which resolver this machine resolves through.
func answerOwnResolver(f Facts) Answer {
	const (
		label    = "Own DNS"
		question = "Do you have your own DNS service?"
	)

	effective := reachable(f.Resolvers)
	if len(effective) == 0 {
		return unknownAnswer(label, question,
			"not measured: no reachable resolver is configured",
			"Restore the network connection, then run the check again")
	}

	var public []string
	for _, r := range effective {
		if r.Kind == sysdns.KindPublic && !r.Encrypted() {
			public = append(public, resolverLabel(r))
		}
	}

	var (
		state   = StateGood
		summary = "Yes. Resolution runs through " + joinLabels(effective) + "."
		fix     *Fix
		reasons []string
	)
	if len(public) > 0 {
		state = StateWarn
		reasons = append(reasons, "a public resolver answers in the clear")
		summary = "Partly. Resolution runs through " + joinLabels(effective) +
			". A public resolver answers in the clear for part of the namespace."
		fix = tunnelResolverFix(f, effective)
	}
	if f.TotalServices > 0 && f.ExplicitServices == 0 {
		reasons = append(reasons, "no service has a hand-set server")
		summary += " No service has a hand-set server, so the resolver was not chosen here."
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "resolution runs through "+joinLabels(effective))
	}
	if len(f.EncryptedProfiles) > 0 {
		summary += fmt.Sprintf(" An encrypted profile is configured in %s.",
			sysdns.ResolverDir+" ("+strings.Join(f.EncryptedProfiles, ", ")+")")
	}

	return Answer{
		Label:    label,
		Question: question,
		State:    state,
		Hint:     strings.Join(reasons, "; "),
		Summary:  summary,
		Fix:      fix,
	}
}

// tunnelResolverFix names the service and the address to write, but only when
// both are known. A command with a placeholder is worse than no command.
func tunnelResolverFix(f Facts, effective []ResolverView) *Fix {
	fix := &Fix{
		Severity: StateWarn,
		Text:     "Point every network service at the resolver your tunnel provides",
	}
	if len(f.ServiceNames) != 1 {
		return fix
	}
	var local []ResolverView
	for _, r := range effective {
		if r.Kind.TunnelLocal() {
			local = append(local, r)
		}
	}
	if len(local) == 0 {
		return fix
	}
	fix.Command = fmt.Sprintf("networksetup -setdnsservers %q %s",
		f.ServiceNames[0], local[0].Addr)
	return fix
}

// answerProxyCoverage reports whether every lookup leaves through the tunnel.
func answerProxyCoverage(f Facts) Answer {
	const (
		label    = "All DNS via proxy"
		question = "Does all DNS go through the proxy?"
	)

	effective := reachable(f.Resolvers)
	if len(effective) == 0 {
		return unknownAnswer(label, question,
			"not measured: no reachable resolver is configured",
			"Restore the network connection, then run the check again")
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

	var (
		state   = StateGood
		summary = "Yes. Lookups leave through " + joinLabels(effective) +
			", which answers from the tunnel exit."
		fix *Fix
		// reasons accumulate so a second finding adds to the line instead of
		// replacing what the first one said.
		reasons []string
	)
	if len(offTunnel) > 0 {
		state = StateUnmanaged
		reasons = append(reasons, joinAnd(offTunnel)+" "+agree(len(offTunnel), "answers", "answer")+
			" from outside the tunnel exit")
		summary = "No. " + joinAnd(offTunnel) +
			" answers from outside the tunnel exit, so lookups bypass the proxy."
		fix = &Fix{
			Severity: StateUnmanaged,
			Text:     "Route " + joinAnd(offTunnel) + " through the tunnel, or remove it",
		}
	}
	if f.PlaintextUDP {
		if fix == nil || fix.Severity > StateWarn {
			fix = &Fix{
				Severity: StateWarn,
				Text:     "Block outbound port 53 so only the tunnel resolver stays reachable",
			}
		}
		reasons = append(reasons, "cleartext DNS completes to a public resolver on port 53")
		summary += " Cleartext DNS still completes to a public resolver on port 53."
	}
	if len(f.IPv6Bypass) > 0 {
		reasons = append(reasons, "an IPv6 address is active outside the tunnel")
		summary += fmt.Sprintf(" An IPv6 address is active outside the tunnel (%s), "+
			"so a v6 path can bypass it.", joinAnd(f.IPv6Bypass))
		if fix == nil {
			fix = &Fix{
				Severity: StateWarn,
				Text:     "Route IPv6 through the tunnel, or turn it off for " + f.IPv6Bypass[0],
			}
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "lookups leave through "+joinLabels(effective)+" from the tunnel exit")
	} else {
		// Only a reason that describes a defect can downgrade the verdict.
		state = lower(state, StateWarn)
	}

	return Answer{
		Label:    label,
		Question: question,
		State:    state,
		Hint:     strings.Join(reasons, "; "),
		Summary:  summary,
		Fix:      fix,
	}
}

// answerHijack reports whether unknown names were rewritten into addresses.
func answerHijack(f Facts) Answer {
	const (
		label    = "DNS hijacking"
		question = "Is there DNS hijacking?"
	)

	if len(f.Hijack.Probed) == 0 {
		return unknownAnswer(label, question,
			"not measured: the reserved-name probe did not complete",
			"Run the check again on a network with working resolution")
	}
	if !f.Hijack.Hijacked() {
		return Answer{
			Label:    label,
			Question: question,
			State:    StateGood,
			Hint:     fmt.Sprintf("none found in %d probes", len(f.Hijack.Probed)),
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
		Label:    label,
		Question: question,
		State:    StateUnmanaged,
		Hint: fmt.Sprintf("%d of %d names rewritten into addresses",
			len(f.Hijack.Answers), len(f.Hijack.Probed)),
		Summary: fmt.Sprintf("Yes. %d of %d names that cannot exist were rewritten into addresses: %s.",
			len(f.Hijack.Answers), len(f.Hijack.Probed), strings.Join(labels, "; ")),
		Fix: &Fix{
			Severity: StateUnmanaged,
			Text:     "Move to a resolver you trust, or point the tunnel at one",
		},
	}
}

// answerLeak reports whether the names are resolved by someone outside the tunnel.
func answerLeak(f Facts) Answer {
	const (
		label    = "DNS leakage"
		question = "Is there DNS leakage?"
	)

	if f.Egress == nil {
		return unknownAnswer(label, question,
			"not measured: the tunnel exit could not be read",
			"Restore outbound HTTPS, then run the check again")
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
		return unknownAnswer(label, question,
			"not measured: no resolver reported its source address",
			"Run the check again on a network with working resolution")
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
		unmeasuredNote = fmt.Sprintf(" The path of %s could not be measured.", joinAnd(labels))
	}

	if len(leaked) == 0 {
		summary := fmt.Sprintf("None found. Every resolver that reported its source address (%d of %d) "+
			"answers from the tunnel exit %s.%s", checked, checked+len(unmeasured), exit, unmeasuredNote)
		return Answer{
			Label:    label,
			Question: question,
			State:    StateGood,
			Hint:     fmt.Sprintf("no leak from %s", pluralResolvers(checked)),
			Summary:  summary,
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
			Label:    label,
			Question: question,
			State:    StateWarn,
			Hint:     "resolvers sit in the exit network, in the clear",
			Summary: fmt.Sprintf("Not outside the tunnel, but not protected. Traffic exits at %s and the resolvers "+
				"answer from the same network in the clear: %s.%s", exit, joinAnd(parts), unmeasuredNote),
			Fix: &Fix{
				Severity: StateWarn,
				Text:     "Encrypt the resolver with DoH or DoT",
			},
		}
	}
	return Answer{
		Label:    label,
		Question: question,
		State:    StateUnmanaged,
		Hint:     joinAnd(parts) + " " + agree(len(parts), "answers", "answer") + " from outside the tunnel",
		Summary: fmt.Sprintf("Yes. Traffic exits at %s, but these resolvers answer from a different source: %s.%s",
			exit, joinAnd(parts), unmeasuredNote),
		Fix: &Fix{
			Severity: StateUnmanaged,
			Text:     "Route these resolvers through the tunnel so the exit and the resolver agree",
		},
	}
}

// lower returns the worse of two states.
func lower(a, b State) State {
	if a < b {
		return a
	}
	return b
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

// pluralResolvers renders a resolver count as a noun phrase.
func pluralResolvers(n int) string {
	if n == 1 {
		return "1 resolver"
	}
	return fmt.Sprintf("%d resolvers", n)
}

// agree picks the verb form that fits the number of subjects, so a list of one
// does not read as a list of many.
func agree(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
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
