// Package resolvconf reads the resolver configuration a Linux process actually
// uses.
//
// Every Linux DNS stack ends at /etc/resolv.conf, whether it was written by
// systemd-resolved, NetworkManager, resolvconf or the init script, so that file
// is the base. The stacks are then probed in addition, because each can report a
// resolver that the file only points at.
package resolvconf

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Path is the resolver file every Linux process reads.
const Path = "/etc/resolv.conf"

// Source names the stack that wrote the configuration.
const (
	// SourceResolvConf is a file written directly, or by an init script.
	SourceResolvConf = "resolv.conf"
	// SourceResolved is systemd-resolved.
	SourceResolved = "systemd-resolved"
	// SourceNetworkManager is NetworkManager.
	SourceNetworkManager = "networkmanager"
	// SourceResolvconf is the resolvconf shim.
	SourceResolvconf = "resolvconf"
)

// Config is the resolver state of one Linux machine.
type Config struct {
	// Source names the stack that produced the configuration.
	Source string
	// Servers are the nameserver addresses in configured order.
	Servers []netip.Addr
	// Search lists the resolver search domains.
	Search []string
	// Options holds the resolver options, such as ndots.
	Options []string
	// Stub is the local address the file points at, when the real resolver sits
	// behind it. systemd-resolved uses 127.0.0.53 and a container runtime injects
	// an address below 0.1.
	Stub netip.Addr
	// Upstreams are the resolvers behind the stub, as reported by the stack that
	// owns it.
	Upstreams []netip.Addr
	// Configured reports whether the file sits outside the managed paths, which
	// is what separates a hand-written resolver from one rewritten on every boot.
	Configured bool
}

// IsStub reports whether the address forwards to another resolver rather than
// resolving names itself.
//
// systemd-resolved listens on 127.0.0.53 and a container runtime injects an
// address in 0.0.0.0/8, for example 0.250.250.200. Both read as ordinary global
// addresses to the standard library, which would report a local door as a
// cleartext resolver on the public internet.
func IsStub(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	if addr.IsLoopback() {
		return true
	}
	return addr.As4()[0] == 0
}

// managedPrefixes are the paths a network manager rewrites on every boot. A
// resolver file under one of them was not chosen by anyone.
var managedPrefixes = []string{
	"/run/systemd/resolve/",
	"/run/NetworkManager/",
	"/run/resolvconf/",
	"/var/run/systemd/resolve/",
	"/var/run/NetworkManager/",
	"/var/run/resolvconf/",
}

// Read reads the resolver configuration of this machine.
func Read() (Config, error) {
	cfg, err := ReadFile(Path)
	if err != nil {
		return cfg, err
	}

	target, err := filepath.EvalSymlinks(Path)
	if err != nil {
		target = Path
	}
	cfg.Source = SourceOf(target)
	cfg.Configured = !isManaged(target)

	// The stacks are consulted only for the resolvers behind a stub, because the
	// file is authoritative about what a query uses.
	if cfg.Stub.IsValid() {
		if upstreams := readUpstreams(); len(upstreams) > 0 {
			cfg.Upstreams = upstreams
		}
	}
	return cfg, nil
}

// ReadFile parses one resolver file.
func ReadFile(path string) (Config, error) {
	cfg := Config{Source: SourceResolvConf}

	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "nameserver":
			addr, err := netip.ParseAddr(value)
			if err != nil {
				continue
			}
			cfg.Servers = append(cfg.Servers, addr)
		case "search", "domain":
			cfg.Search = append(cfg.Search, strings.Fields(value)...)
		case "options":
			cfg.Options = append(cfg.Options, strings.Fields(value)...)
		}
	}
	if err := sc.Err(); err != nil {
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}

	// A lone stub address is a door to another resolver, not a resolver itself.
	if len(cfg.Servers) == 1 && IsStub(cfg.Servers[0]) {
		cfg.Stub = cfg.Servers[0]
	}
	return cfg, nil
}

// SourceOf names the stack that wrote the file at the given path.
func SourceOf(path string) string {
	switch {
	case strings.Contains(path, "systemd/resolve/"):
		return SourceResolved
	case strings.Contains(path, "NetworkManager/"):
		return SourceNetworkManager
	case strings.Contains(path, "resolvconf/"):
		return SourceResolvconf
	default:
		return SourceResolvConf
	}
}

// isManaged reports whether the file sits under a path a network manager
// rewrites on every boot. A resolver found there was not chosen by anyone, so
// it does not count as an explicit configuration.
func isManaged(path string) bool {
	for _, prefix := range managedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// readUpstreams asks whichever stack owns the stub which resolvers sit behind
// it. The first one that answers wins, because a host runs one of them.
func readUpstreams() []netip.Addr {
	if resolved := readResolved(); len(resolved.Servers) > 0 {
		return resolved.Servers
	}
	if nm := readNetworkManager(); len(nm.Servers) > 0 {
		return nm.Servers
	}
	if rc := readResolvconfInterface(); len(rc.Servers) > 0 {
		return rc.Servers
	}
	return nil
}

// readResolved asks systemd-resolved what the resolvers behind its stub are.
func readResolved() Config {
	out, err := execCommand("resolvectl", "dns")
	if err != nil {
		return Config{}
	}
	return parseResolved(out)
}

// parseResolved reads the "DNS Servers:" lines of `resolvectl dns`.
//
// The addresses continue onto following lines, so the run is consumed until a
// line arrives that is not made of addresses.
func parseResolved(out string) Config {
	cfg := Config{Source: SourceResolved}
	inServers := false

	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		if idx := strings.Index(line, "DNS Servers:"); idx >= 0 {
			inServers = true
			cfg.addServers(strings.Fields(line[idx+len("DNS Servers:"):]))
			continue
		}
		// An IPv6 address carries colons of its own, so a continuation line is
		// recognised by every one of its fields parsing rather than by its shape.
		fields := strings.Fields(line)
		if !allAddresses(fields) {
			inServers = false
			continue
		}
		if inServers {
			cfg.addServers(fields)
		}
	}
	return cfg
}

// allAddresses reports whether every field is an address.
func allAddresses(fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if _, err := netip.ParseAddr(f); err != nil {
			return false
		}
	}
	return true
}

// addServers keeps the addresses that parse.
func (c *Config) addServers(fields []string) {
	for _, field := range fields {
		if addr, err := netip.ParseAddr(field); err == nil {
			c.Servers = append(c.Servers, addr)
		}
	}
}

// readNetworkManager asks NetworkManager for the resolvers it configured.
func readNetworkManager() Config {
	out, err := execCommand("nmcli", "--terse", "--fields", "IP4.DNS,IP6.DNS", "device", "show")
	if err != nil {
		return Config{}
	}
	return parseNetworkManager(out)
}

// parseNetworkManager reads the terse IP4.DNS and IP6.DNS fields, which are
// semicolon separated.
func parseNetworkManager(out string) Config {
	cfg := Config{Source: SourceNetworkManager}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "IP4.DNS") && !strings.HasPrefix(line, "IP6.DNS") {
			continue
		}
		_, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		for _, field := range strings.Split(value, ";") {
			if addr, err := netip.ParseAddr(strings.TrimSpace(field)); err == nil {
				cfg.Servers = append(cfg.Servers, addr)
			}
		}
	}
	return cfg
}

// readResolvconfInterface asks the resolvconf shim which interface it is
// currently using.
func readResolvconfInterface() Config {
	out, err := execCommand("resolvconf", "-l")
	if err != nil {
		return Config{}
	}
	return parseResolvconfInterface(out)
}

// parseResolvconfInterface reads the "nameserver" lines of `resolvconf -l`.
func parseResolvconfInterface(out string) Config {
	cfg := Config{Source: SourceResolvconf}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(strings.TrimSpace(sc.Text()))
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if addr, err := netip.ParseAddr(fields[1]); err == nil {
			cfg.Servers = append(cfg.Servers, addr)
		}
	}
	return cfg
}

// EncryptedProfiles lists the systemd-resolved settings that turn on encrypted
// DNS, from the drop-in directory systemd reads. The files are absent when the
// feature is off, which is the common case.
func EncryptedProfiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	var out []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		out = append(out, encryptedIn(filepath.Join(dir, entry.Name()))...)
	}
	return out, nil
}

// encryptedIn reads the encrypted DNS setting out of one drop-in file.
func encryptedIn(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if strings.EqualFold(key, "DNSOverTLS") && !strings.EqualFold(value, "no") {
			out = append(out, filepath.Base(path)+" DNSOverTLS="+value)
		}
	}
	return out
}
