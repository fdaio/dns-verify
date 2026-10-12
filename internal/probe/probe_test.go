package probe

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseIPField(t *testing.T) {
	cases := []struct {
		field string
		want  string
		ok    bool
	}{
		{`"192.0.2.33"`, "192.0.2.33", true},
		{"198.51.100.7", "198.51.100.7", true},
		{"2001:db8::1", "2001:db8::1", true},
		{"edns0-client-subnet 203.0.113.0/24", "", false},
		{"edns0-client-subnet", "", false},
		{`"not an address"`, "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := parseIPField(c.field)
		if ok != c.ok {
			t.Errorf("parseIPField(%q) ok = %v, want %v", c.field, ok, c.ok)
			continue
		}
		if ok && got.String() != c.want {
			t.Errorf("parseIPField(%q) = %v, want %v", c.field, got, c.want)
		}
	}
}

func TestParseOrigin(t *testing.T) {
	cases := []struct {
		text    string
		asn     uint32
		prefix  string
		country string
		ok      bool
	}{
		{`"64500 | 198.51.100.0/24 | DE | ripe | 2020-01-01"`, 64500, "198.51.100.0/24", "DE", true},
		{`"64501 | 203.0.113.0/24 | NL | ripe | 2021-01-01"`, 64501, "203.0.113.0/24", "NL", true},
		{"", 0, "", "", false},
		{`"NA | 0.0.0.0/0 | ZZ | reserved"`, 0, "", "", false},
		{`"not a record"`, 0, "", "", false},
	}
	for _, c := range cases {
		got, ok := parseOrigin(c.text)
		if ok != c.ok {
			t.Errorf("parseOrigin(%q) ok = %v, want %v", c.text, ok, c.ok)
			continue
		}
		if ok && (got.ASN != c.asn || got.Prefix != c.prefix || got.Country != c.country) {
			t.Errorf("parseOrigin(%q) = %+v, want AS%d %s %s", c.text, got, c.asn, c.prefix, c.country)
		}
	}
}

// The origin service expects the octets in reverse order, written as one hex
// label. Anything else returns no result.
func TestReverseNibbles(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"1.1.1.1", "01010101"},
		{"192.0.2.33", "210200c0"},
		{"223.5.5.5", "050505df"},
	}
	for _, c := range cases {
		addr := netip.MustParseAddr(c.addr)
		raw := addr.As4()
		if got := reverseNibbles(raw[:]); got != c.want {
			t.Errorf("reverseNibbles(%s) = %s, want %s", c.addr, got, c.want)
		}
	}
}

func TestOriginQueryName(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"1.1.1.1", "01010101.origin.asn.cymru.com"},
		{"192.0.2.33", "210200c0.origin.asn.cymru.com"},
		{"2001:db8::1", "010000000000000000000000b80d0120.origin6.asn.cymru.com"},
	}
	for _, c := range cases {
		got := originQueryName(netip.MustParseAddr(c.addr))
		if got != c.want {
			t.Errorf("originQueryName(%s) = %q, want %q", c.addr, got, c.want)
		}
	}
}

func TestOriginString(t *testing.T) {
	if got := (Origin{ASN: 64500}).String(); got != "AS64500" {
		t.Errorf("Origin.String() = %q, want AS64500", got)
	}
}

func TestHijackResultHijacked(t *testing.T) {
	empty := HijackResult{Probed: []string{"a.example.com"}}
	if empty.Hijacked() {
		t.Error("a probe without rewrites is not hijacked")
	}
	hijacked := HijackResult{
		Probed:  []string{"a.example.com"},
		Answers: map[string][]netip.Addr{"a.example.com": {netip.MustParseAddr("45.33.32.156")}},
	}
	if !hijacked.Hijacked() {
		t.Error("a rewritten answer is hijacking")
	}
}

// A label must be long enough that no zone can hold it, and it must vary so a
// cached answer from an earlier run cannot pass as a clean result.
func TestRandomLabel(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		label := randomLabel()
		if len(label) != 32 {
			t.Fatalf("label %q has length %d, want 32", label, len(label))
		}
		if strings.Trim(label, "0123456789abcdef") != "" {
			t.Fatalf("label %q is not hex", label)
		}
		seen[label] = true
	}
	if len(seen) != 100 {
		t.Errorf("got %d distinct labels out of 100", len(seen))
	}
}

func TestResolverString(t *testing.T) {
	cases := []struct {
		resolver Resolver
		want     string
	}{
		{Resolver{Addr: netip.MustParseAddr("1.1.1.1")}, "1.1.1.1:53"},
		{Resolver{Addr: netip.MustParseAddr("1.1.1.1"), Port: 853}, "1.1.1.1:853"},
		{Resolver{Addr: netip.MustParseAddr("2001:db8::1")}, "[2001:db8::1]:53"},
	}
	for _, c := range cases {
		if got := c.resolver.String(); got != c.want {
			t.Errorf("Resolver.String() = %q, want %q", got, c.want)
		}
	}
}
