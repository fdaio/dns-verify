// Package run performs one full DNS check and assembles the measurements the
// report is built from.
package run

import (
	"context"
	"net/netip"
	"sync"

	"github.com/fdaio/dns-verify/internal/analyze"
	"github.com/fdaio/dns-verify/internal/probe"
	"github.com/fdaio/dns-verify/internal/sysdns"
)

// hijackProbes is the number of unresolvable names sent to each reserved domain.
const hijackProbes = 2

// fakeIPTarget is resolved once to see whether a TUN client substitutes fake
// addresses for real ones.
const fakeIPTarget = "example.com"

// lookupResolver is used for lookups that are not about the machine's own path,
// such as the origin of an address. It only asks for a fact the tunnel cannot
// change.
var lookupResolver = probe.Resolver{Addr: netip.MustParseAddr("1.1.1.1")}

// escapeResolvers are probed with cleartext DNS to find out whether an open port
// 53 can leave the machine.
var escapeResolvers = []netip.Addr{
	netip.MustParseAddr("1.1.1.1"),
	netip.MustParseAddr("8.8.8.8"),
}

// Observer receives the stages of a run so a caller can show progress. Every
// method must be safe to call on a nil Observer, which is how the check runs
// when the output cannot show anything.
type Observer interface {
	// Start names a stage. total is the size of the whole run, not of the
	// stage, so a caller can lay the progress line out against one figure.
	Start(label string, total int)
	// Advance completes one step of the current stage.
	Advance()
}

// nopObserver is used when nothing is watching.
type nopObserver struct{}

func (nopObserver) Start(string, int) {}
func (nopObserver) Advance()          {}

// stageSizes are the step counts of the parts of a run that are watched, kept
// together so the total can be computed before the first stage starts.
type stageSizes struct {
	egress   int
	resolver int
	hijack   int
	origins  int
}

// total is the number of steps a run performs. The progress bar is drawn
// against it, so it must match what the stages actually advance.
func (s stageSizes) total() int {
	return s.egress + s.resolver + s.hijack + s.origins
}

// RunWith performs the check and reports each stage to the observer.
func RunWith(ctx context.Context, obs Observer) (analyze.Report, error) {
	if obs == nil {
		obs = nopObserver{}
	}

	// The configuration is read before the progress line starts. It is a local
	// command that answers in well under a tenth of a second, and the number of
	// resolvers it returns is what the total is built from, so the first frame
	// already carries a count that will not change width.
	cfg, err := sysdns.System(ctx)
	if err != nil {
		return analyze.Report{}, err
	}

	facts := analyze.Facts{
		Origins:   make(map[string]probe.Origin),
		Resolvers: resolverViews(cfg),
	}
	facts.ServiceNames, facts.ExplicitServices, facts.TotalServices =
		explicitServices(ctx, facts.Resolvers)
	facts.EncryptedProfiles = encryptedProfiles()
	if addrs, err := sysdns.IPv6Bypass(); err == nil {
		facts.IPv6Bypass = addrs
	}

	total := stageSizes{
		egress:   1,
		resolver: len(facts.Resolvers),
		hijack:   len(hijackTargets(facts.Resolvers)),
		origins:  1,
	}.total()

	// The exit address is the reference every other measurement is compared to,
	// so it starts first.
	obs.Start("measuring the tunnel exit", total)
	if egress, err := probe.EgressAddr(ctx); err == nil {
		facts.Egress = &egress
	}
	obs.Advance()

	results := measureResolvers(ctx, facts.Resolvers, total, obs)
	applyResolverResults(&facts, results)

	measureEscape(ctx, &facts)
	measureHijack(ctx, hijackTargets(facts.Resolvers), &facts, total, obs)
	measureOrigins(ctx, &facts, total, obs)

	return analyze.Build(facts), nil
}

// hijackTargets returns the resolvers that get a reserved-name probe.
func hijackTargets(views []analyze.ResolverView) []analyze.ResolverView {
	seen := make(map[netip.Addr]bool)
	var out []analyze.ResolverView
	for _, view := range views {
		if view.Reachable && !seen[view.Addr] {
			seen[view.Addr] = true
			out = append(out, view)
		}
	}
	return out
}

// resolverViews converts the system configuration into the analysis view. The
// entries of one nameserver are collapsed, because a client that routes part of
// the namespace installs one entry per domain it handles.
func resolverViews(cfg sysdns.Config) []analyze.ResolverView {
	var out []analyze.ResolverView
	for _, g := range cfg.Group() {
		port := g.Port
		if port == 0 {
			port = 53
		}
		out = append(out, analyze.ResolverView{
			Addr:          g.Addr,
			Port:          port,
			Kind:          sysdns.Classify(g.Addr),
			Flags:         g.Flags,
			Reachable:     g.Reachable,
			ServesDomains: len(g.Domains),
		})
	}
	return out
}

// explicitServices returns the enabled service names, the number of services
// with a hand-set server, and the total. It also marks the resolvers a human
// chose, because a server the network hands out is not a choice.
func explicitServices(ctx context.Context, views []analyze.ResolverView) ([]string, int, int) {
	services, err := sysdns.ExplicitServers(ctx)
	if err != nil {
		return nil, 0, 0
	}

	names := make([]string, 0, len(services))
	chosen := make(map[netip.Addr]bool)
	for _, service := range services {
		names = append(names, service.Name)
		for _, server := range service.Servers {
			if addr, err := netip.ParseAddr(server); err == nil {
				chosen[addr.Unmap()] = true
			}
		}
	}
	for i := range views {
		views[i].Explicit = chosen[views[i].Addr]
	}
	return names, len(chosen), len(names)
}

// encryptedProfiles lists the encrypted resolver profiles installed on this
// machine.
func encryptedProfiles() []string {
	profiles, err := sysdns.EncryptedProfiles(sysdns.ResolverDir)
	if err != nil {
		return nil
	}
	return append([]string(nil), profiles...)
}

// measurement is what one resolver probe found. Probes run concurrently, so
// each writes only its own value and the results merge afterwards.
type measurement struct {
	echoAddr     netip.Addr
	echoErr      error
	upstreamAddr netip.Addr
	plaintextUDP bool
	plaintextTCP bool
	fakeIP       bool
}

// measureResolvers probes every resolver at once. A run costs several network
// round trips, and a dead resolver must not delay the rest of the report.
func measureResolvers(ctx context.Context, views []analyze.ResolverView,
	total int, obs Observer) []measurement {
	obs.Start("asking resolvers for their source address", total)

	results := make([]measurement, len(views))
	var wg sync.WaitGroup
	for i := range views {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			view := views[i]
			if !view.Reachable {
				obs.Advance()
				return
			}
			results[i] = probeResolver(ctx, probe.Resolver{Addr: view.Addr, Port: view.Port})
			obs.Advance()
		}(i)
	}
	wg.Wait()
	return results
}

func probeResolver(ctx context.Context, resolver probe.Resolver) measurement {
	var m measurement
	if addr, err := probe.ResolverEcho(ctx, resolver); err == nil {
		m.echoAddr = addr
	} else {
		m.echoErr = err
	}
	if addr, err := probe.RecursiveEcho(ctx, resolver); err == nil {
		m.upstreamAddr = addr
	}
	if err := probe.PlaintextReachable(ctx, resolver, "udp"); err == nil {
		m.plaintextUDP = true
	}
	if err := probe.PlaintextReachable(ctx, resolver, "tcp"); err == nil {
		m.plaintextTCP = true
	}
	if addrs, err := probe.ResolvedAddrs(ctx, resolver, fakeIPTarget); err == nil {
		for _, a := range addrs {
			if sysdns.IsFakeIP(a) {
				m.fakeIP = true
			}
		}
	}
	return m
}

func applyResolverResults(facts *analyze.Facts, results []measurement) {
	for i := range facts.Resolvers {
		m := results[i]
		facts.Resolvers[i].EchoAddr = m.echoAddr
		facts.Resolvers[i].EchoErr = m.echoErr
		facts.Resolvers[i].UpstreamAddr = m.upstreamAddr
		facts.Resolvers[i].FakeIP = m.fakeIP
		facts.PlaintextUDP = facts.PlaintextUDP || m.plaintextUDP
		facts.PlaintextTCP = facts.PlaintextTCP || m.plaintextTCP
	}
}

// measureEscape finds out whether cleartext DNS can leave the machine directly.
func measureEscape(ctx context.Context, facts *analyze.Facts) {
	for _, addr := range escapeResolvers {
		resolver := probe.Resolver{Addr: addr}
		if err := probe.PlaintextReachable(ctx, resolver, "udp"); err != nil {
			continue
		}
		facts.PlaintextUDP = true
		if err := probe.PlaintextReachable(ctx, resolver, "tcp"); err == nil {
			facts.PlaintextTCP = true
		}
	}
}

// measureHijack sends unresolvable names through every reachable resolver.
func measureHijack(ctx context.Context, targets []analyze.ResolverView,
	facts *analyze.Facts, total int, obs Observer) {
	obs.Start("probing for hijacked answers", total)
	for _, view := range targets {
		result, err := probe.Hijack(ctx, probe.Resolver{Addr: view.Addr, Port: view.Port}, hijackProbes)
		if err == nil {
			facts.Hijack.Probed = append(facts.Hijack.Probed, result.Probed...)
			for label, addrs := range result.Answers {
				facts.Hijack.Answers[label] = append(facts.Hijack.Answers[label], addrs...)
			}
		}
		obs.Advance()
	}
}

// measureOrigins records the network each observed address belongs to, so the
// report can say whether a resolver sits with the tunnel operator or elsewhere.
//
// The lookups run together and report as one step, because their number is only
// known once the resolvers have answered.
func measureOrigins(ctx context.Context, facts *analyze.Facts, total int, obs Observer) {
	seen := make(map[netip.Addr]bool)
	collect := func(addr netip.Addr) {
		if !addr.IsValid() || seen[addr] {
			return
		}
		seen[addr] = true
		measureOrigin(ctx, facts, addr)
	}

	obs.Start("looking up the network of each address", total)
	if facts.Egress != nil {
		collect(facts.Egress.Addr)
	}
	for _, view := range facts.Resolvers {
		collect(view.EchoAddr)
		collect(view.UpstreamAddr)
	}
	obs.Advance()
}

// measureOrigin looks up one address and records the result.
func measureOrigin(ctx context.Context, facts *analyze.Facts, addr netip.Addr) {
	origin, err := probe.OriginOf(ctx, lookupResolver, addr)
	if err != nil {
		return
	}
	facts.Origins[addr.String()] = origin
	if facts.Egress != nil && facts.Egress.Addr == addr {
		copied := origin
		facts.EgressOrigin = &copied
	}
}
