// Package sysdns reads the DNS configuration that macOS actually applies.
//
// `scutil --dns` is the only source that reflects the merged SystemConfiguration
// state, including resolvers installed by VPN clients. The per-service files in
// /etc/resolver and /etc/resolv.conf cannot show that: on macOS the latter is
// regenerated from the same state and is not consulted by most processes.
package sysdns

import (
	"bufio"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Resolver is one resolver block of `scutil --dns`.
type Resolver struct {
	// Index is the resolver number in the scutil output. It is stable only for
	// one snapshot of the configuration.
	Index int
	// Domain scopes the resolver. Empty means it serves the default search.
	Domain string
	// Search lists the search domains attached to the resolver.
	Search []string
	// Servers are the nameserver addresses, in configured order.
	Servers []netip.Addr
	// Port is the resolver port. It is 53 unless the entry overrides it.
	Port uint16
	// Flags holds the scutil flag names, such as "Supplemental" or "Scoped".
	Flags []string
	// Reachable reports the reachability bit from the scutil output.
	Reachable bool
	// Scoped marks resolvers from the "for scoped queries" section.
	Scoped bool
	// IfIndex and IfName identify the interface the resolver is bound to.
	IfIndex int
	IfName  string
	// MDNS marks resolvers that only serve multicast DNS.
	MDNS bool
}

// HasFlag reports whether the resolver carries the named scutil flag.
func (r Resolver) HasFlag(name string) bool {
	for _, f := range r.Flags {
		if f == name {
			return true
		}
	}
	return false
}

// Config is the parsed resolver state of one machine.
type Config struct {
	// Resolvers holds every resolver from both scutil sections.
	Resolvers []Resolver
}

// Effective returns the resolvers that apply to ordinary name lookups.
// Scoped resolvers serve one interface only, and mDNS entries answer multicast
// queries, so neither takes part in normal resolution.
func (c Config) Effective() []Resolver {
	out := make([]Resolver, 0, len(c.Resolvers))
	for _, r := range c.Resolvers {
		if r.Scoped || r.MDNS || len(r.Servers) == 0 {
			continue
		}
		out = append(out, r)
	}
	return out
}

// SplitScoped returns the resolvers that serve a named domain. A VPN client that
// routes part of the namespace installs one entry per domain it handles.
func (c Config) SplitScoped() []Resolver {
	var out []Resolver
	for _, r := range c.Resolvers {
		if !r.Scoped && r.Domain != "" {
			out = append(out, r)
		}
	}
	return out
}

// UniqueServers returns every distinct server address in the configuration,
// keeping first-seen order.
func (c Config) UniqueServers() []netip.Addr {
	seen := make(map[netip.Addr]bool)
	var out []netip.Addr
	for _, r := range c.Resolvers {
		if r.Scoped || r.MDNS {
			continue
		}
		for _, s := range r.Servers {
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ResolverGroup is one distinct nameserver address together with everything the
// configuration says about it.
type ResolverGroup struct {
	// Addr is the nameserver address.
	Addr netip.Addr
	// Port is the resolver port.
	Port uint16
	// Flags holds the scutil flags seen on any entry that uses the address.
	Flags []string
	// Reachable reports whether any entry using the address is reachable.
	Reachable bool
	// ServesDefault reports whether the address answers without a domain scope.
	ServesDefault bool
	// Domains lists the split-DNS domains routed to this address.
	Domains []string
}

// Group collapses the resolver entries onto the distinct addresses they use.
//
// A VPN client that routes part of the namespace installs one entry per domain,
// so the raw list repeats the same address dozens of times. What a check must
// report is the set of servers that answer, not the number of zone scopes.
func (c Config) Group() []ResolverGroup {
	var order []netip.Addr
	byAddr := make(map[netip.Addr]*ResolverGroup)

	for _, r := range c.Effective() {
		for _, addr := range r.Servers {
			group, ok := byAddr[addr]
			if !ok {
				group = &ResolverGroup{Addr: addr, Port: r.Port}
				byAddr[addr] = group
				order = append(order, addr)
			}
			if group.Port == 0 {
				group.Port = r.Port
			}
			group.Reachable = group.Reachable || r.Reachable
			group.Flags = appendMissing(group.Flags, r.Flags)
			if r.Domain == "" {
				group.ServesDefault = true
				continue
			}
			group.Domains = appendMissing(group.Domains, []string{r.Domain})
		}
	}

	out := make([]ResolverGroup, 0, len(order))
	for _, addr := range order {
		out = append(out, *byAddr[addr])
	}
	return out
}

// appendMissing adds the entries of extra that group does not have yet.
func appendMissing(group, extra []string) []string {
	for _, e := range extra {
		found := false
		for _, g := range group {
			if g == e {
				found = true
				break
			}
		}
		if !found {
			group = append(group, e)
		}
	}
	return group
}

// Parse reads the output of `scutil --dns`.
func Parse(output string) (Config, error) {
	var (
		cfg     Config
		current *Resolver
		scoped  bool
	)

	finish := func() {
		if current != nil {
			cfg.Resolvers = append(cfg.Resolvers, *current)
			current = nil
		}
	}

	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Section headers end the current resolver and switch the scope flag.
		if strings.HasPrefix(trimmed, "DNS configuration") {
			finish()
			scoped = strings.Contains(trimmed, "scoped")
			continue
		}

		if strings.HasPrefix(trimmed, "resolver #") {
			finish()
			index, err := strconv.Atoi(strings.TrimPrefix(trimmed, "resolver #"))
			if err != nil {
				return cfg, fmt.Errorf("scutil --dns: bad resolver header %q", trimmed)
			}
			current = &Resolver{Index: index, Port: 53, Scoped: scoped}
			continue
		}

		if current == nil {
			continue
		}

		key, value, ok := splitEntry(line)
		if !ok {
			continue
		}
		if err := current.apply(key, value); err != nil {
			return cfg, err
		}
	}
	if err := sc.Err(); err != nil {
		return cfg, fmt.Errorf("scutil --dns: %w", err)
	}
	finish()
	return cfg, nil
}

// splitEntry separates "  nameserver[0] : 1.1.1.1" into its key and value.
// Indexed keys keep their base name, because the index carries no meaning.
func splitEntry(line string) (key, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	colon := strings.Index(trimmed, ":")
	if colon < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(trimmed[:colon])
	if open := strings.Index(key, "["); open >= 0 {
		key = key[:open]
	}
	value = strings.TrimSpace(trimmed[colon+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

func (r *Resolver) apply(key, value string) error {
	switch key {
	case "domain":
		r.Domain = value
	case "nameserver":
		addr, err := netip.ParseAddr(value)
		if err != nil {
			// A malformed entry must not hide the resolvers that parsed.
			return nil
		}
		r.Servers = append(r.Servers, addr)
	case "search domain":
		r.Search = append(r.Search, value)
	case "port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("scutil --dns: bad port %q", value)
		}
		r.Port = uint16(port)
	case "flags":
		r.Flags = append(r.Flags, splitFlags(value)...)
	case "options":
		if value == "mdns" {
			r.MDNS = true
		}
	case "reach":
		r.Reachable = strings.Contains(value, "(Reachable)") &&
			!strings.Contains(value, "Not Reachable")
	case "if_index":
		r.IfIndex, r.IfName = parseIfIndex(value)
	}
	return nil
}

// parseIfIndex reads "21 (en10)" into its number and name.
func parseIfIndex(value string) (int, string) {
	name := ""
	if open := strings.Index(value, "("); open >= 0 {
		if close := strings.LastIndex(value, ")"); close > open {
			name = value[open+1 : close]
		}
	}
	number := strings.Fields(value)
	if len(number) == 0 {
		return 0, name
	}
	index, err := strconv.Atoi(number[0])
	if err != nil {
		return 0, name
	}
	return index, name
}

// splitFlags separates "Supplemental, Request A records" into its names. The last
// two words are a description, not a flag, so they are dropped.
func splitFlags(value string) []string {
	fields := strings.Split(value, ",")
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.Contains(f, " ") {
			continue
		}
		out = append(out, f)
	}
	return out
}
