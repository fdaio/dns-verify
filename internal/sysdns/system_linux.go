//go:build linux

package sysdns

import (
	"context"
	"net/netip"
	"strings"

	"github.com/fdaio/dns-verify/internal/sysdns/resolvconf"
)

// System reads the resolver configuration this machine applies.
//
// Every Linux DNS stack ends at /etc/resolv.conf, so that file is the base. The
// stack that wrote it is followed through its symlink, and the stack is asked
// directly when it owns a stub, so the report names the resolver a query
// actually reaches rather than the door in front of it.
func System(_ context.Context) (Config, error) {
	linux, err := resolvconf.Read()
	if err != nil {
		return Config{}, err
	}

	cfg := Config{}
	for _, addr := range effectiveServers(linux) {
		cfg.Resolvers = append(cfg.Resolvers, Resolver{
			Index:     len(cfg.Resolvers) + 1,
			Servers:   []netip.Addr{addr},
			Port:      53,
			Flags:     flagsFor(linux),
			Reachable: true,
		})
	}
	return cfg, nil
}

// effectiveServers returns the addresses a query actually reaches. A stub is a
// door, so the resolvers behind it are what count.
func effectiveServers(linux resolvconf.Config) []netip.Addr {
	if len(linux.Upstreams) > 0 {
		return linux.Upstreams
	}
	return linux.Servers
}

// flagsFor records what the source knows about its resolvers.
func flagsFor(linux resolvconf.Config) []string {
	flags := []string{"Default"}
	if linux.Source != "" {
		flags = append(flags, linux.Source)
	}
	if linux.Configured {
		flags = append(flags, "Configured")
	}
	return flags
}

// ExplicitServers reports the resolvers a person chose.
//
// A network manager rewrites the file on every boot, so a resolver found under
// one of its paths was not chosen by anyone. A hand-written file counts, and its
// search domains are returned as the service name so a fix can name it.
func ExplicitServers(_ context.Context) ([]Service, error) {
	linux, err := resolvconf.Read()
	if err != nil {
		return nil, err
	}
	if !linux.Configured {
		return nil, nil
	}

	name := "resolv.conf"
	if len(linux.Search) > 0 {
		name = strings.Join(linux.Search, " ")
	}
	var servers []string
	for _, addr := range effectiveServers(linux) {
		servers = append(servers, addr.String())
	}
	return []Service{{Name: name, Servers: servers}}, nil
}
