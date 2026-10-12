package sysdns

import (
	"net/netip"
	"testing"
)

// scutilOutput is the shape scutil prints on a machine with a mesh VPN client:
// a default resolver, per-domain entries for the zones the client routes, an
// mDNS entry, and a second section for interface-scoped resolvers.
const scutilOutput = `DNS configuration

resolver #1
  search domain[0] : netbird.cloud
  nameserver[0] : 100.101.255.254
  port     : 53
  flags    : Supplemental, Request A records
  reach    : 0x00000002 (Reachable)
  order    : 101800

resolver #2
  nameserver[0] : 223.5.5.5
  nameserver[1] : 8.8.8.8
  if_index : 21 (en10)
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
  order    : 200000

resolver #3
  domain   : github.com
  nameserver[0] : 100.101.255.254
  port     : 53
  flags    : Supplemental, Request A records
  reach    : 0x00000002 (Reachable)
  order    : 102407

resolver #4
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
  if_index : 12 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00000002 (Reachable)
`

func TestParseIndexedKeys(t *testing.T) {
	cfg, err := Parse(scutilOutput)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Resolvers) != 5 {
		t.Fatalf("got %d resolvers, want 5", len(cfg.Resolvers))
	}

	first := cfg.Resolvers[0]
	if got, want := first.Servers, []netip.Addr{netip.MustParseAddr("100.101.255.254")}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("first nameserver = %v, want %v", got, want)
	}
	if len(first.Search) != 1 || first.Search[0] != "netbird.cloud" {
		t.Errorf("search domains = %v, want [netbird.cloud]", first.Search)
	}
	if first.Port != 53 {
		t.Errorf("port = %d, want 53", first.Port)
	}
	if !first.Reachable {
		t.Error("first resolver should be reachable")
	}
	if !first.HasFlag("Supplemental") {
		t.Error("first resolver should carry the Supplemental flag")
	}
	if first.HasFlag("Request A records") {
		t.Error("a description must not be read as a flag")
	}

	second := cfg.Resolvers[1]
	if len(second.Servers) != 2 {
		t.Fatalf("second resolver servers = %v, want 2 entries", second.Servers)
	}
	if second.IfIndex != 21 || second.IfName != "en10" {
		t.Errorf("if_index = %d/%q, want 21/en10", second.IfIndex, second.IfName)
	}

	mdns := cfg.Resolvers[3]
	if !mdns.MDNS {
		t.Error("resolver #4 should be marked as mDNS")
	}
	if mdns.Reachable {
		t.Error("a Not Reachable entry must not be reported as reachable")
	}

	scoped := cfg.Resolvers[4]
	if !scoped.Scoped {
		t.Error("the last resolver comes from the scoped section")
	}
}

func TestEffectiveDropsScopedAndMDNS(t *testing.T) {
	cfg, err := Parse(scutilOutput)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	effective := cfg.Effective()
	if len(effective) != 3 {
		t.Fatalf("got %d effective resolvers, want 3", len(effective))
	}
	for _, r := range effective {
		if r.MDNS || r.Scoped {
			t.Errorf("resolver #%d should have been dropped", r.Index)
		}
	}
}

func TestGroupCollapsesRepeatedAddresses(t *testing.T) {
	cfg, err := Parse(scutilOutput)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	groups := cfg.Group()
	if len(groups) != 3 {
		t.Fatalf("got %d resolver groups, want 3: %+v", len(groups), groups)
	}

	overlay := groups[0]
	if got := overlay.Addr.String(); got != "100.101.255.254" {
		t.Errorf("first group = %s, want 100.101.255.254", got)
	}
	if !overlay.ServesDefault {
		t.Error("the default search must be marked as served")
	}
	if len(overlay.Domains) != 1 || overlay.Domains[0] != "github.com" {
		t.Errorf("overlay domains = %v, want [github.com]", overlay.Domains)
	}

	public := groups[1]
	if got := public.Addr.String(); got != "223.5.5.5" {
		t.Errorf("second group = %s, want 223.5.5.5", got)
	}
	if !public.Reachable {
		t.Error("the public resolver is reachable")
	}
}

func TestGroupKeepsBothServersOfOneEntry(t *testing.T) {
	cfg, err := Parse(scutilOutput)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	var found int
	for _, g := range cfg.Group() {
		if g.Addr.String() == "8.8.8.8" {
			found++
		}
	}
	if found != 1 {
		t.Errorf("the fallback server must survive the grouping, got %d matches", found)
	}
}

func TestParseRejectsBadResolverHeader(t *testing.T) {
	if _, err := Parse("resolver #oops\n  nameserver[0] : 1.1.1.1\n"); err == nil {
		t.Fatal("a malformed header must be reported")
	}
}

func TestParseIgnoresMalformedNameserver(t *testing.T) {
	cfg, err := Parse("resolver #1\n  nameserver[0] : not-an-address\n  reach : 0x00000002 (Reachable)\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Resolvers[0].Servers) != 0 {
		t.Errorf("a bad address must not be stored, got %v", cfg.Resolvers[0].Servers)
	}
	if !cfg.Resolvers[0].Reachable {
		t.Error("the rest of the entry must still be parsed")
	}
}
