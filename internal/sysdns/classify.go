package sysdns

import (
	"net/netip"
	"strings"
)

// Kind classifies a resolver address by who operates it. The distinction
// matters because only some kinds keep queries inside a tunnel.
type Kind int

const (
	// KindUnknown is an address that no rule matched.
	KindUnknown Kind = iota
	// KindLoopback is a resolver on this host, such as a client DNS daemon.
	KindLoopback
	// KindOverlay is a resolver inside a mesh VPN address space, such as
	// NetBird's 100.101.255.254 or Tailscale's 100.100.100.100.
	KindOverlay
	// KindFakeIP is a resolver in the benchmark range that TUN clients use to
	// hand out fake addresses.
	KindFakeIP
	// KindPrivate is a resolver on the local network.
	KindPrivate
	// KindPublic is a resolver on the public internet.
	KindPublic
)

// String returns the label used in reports.
func (k Kind) String() string {
	switch k {
	case KindLoopback:
		return "local"
	case KindOverlay:
		return "overlay"
	case KindFakeIP:
		return "fake-ip"
	case KindPrivate:
		return "private"
	case KindPublic:
		return "public"
	default:
		return "unknown"
	}
}

// overlayNet is the shared address space of the mesh VPN clients that install
// an embedded DNS resolver on the host.
var overlayNet = netip.MustParsePrefix("100.64.0.0/10")

// fakeIPNet is the benchmark range that TUN clients hand out in place of real
// addresses. Traffic to these addresses can only leave through the tunnel.
var fakeIPNet = netip.MustParsePrefix("198.18.0.0/16")

// IsFakeIP reports whether the address belongs to the fake-IP range.
func IsFakeIP(addr netip.Addr) bool {
	return fakeIPNet.Contains(addr)
}

// Classify returns the kind of the given resolver address.
func Classify(addr netip.Addr) Kind {
	switch {
	case !addr.IsValid():
		return KindUnknown
	case addr.IsLoopback():
		return KindLoopback
	case overlayNet.Contains(addr):
		return KindOverlay
	case fakeIPNet.Contains(addr):
		return KindFakeIP
	case addr.IsPrivate() || addr.IsLinkLocalUnicast():
		return KindPrivate
	case addr.IsGlobalUnicast():
		return KindPublic
	default:
		return KindUnknown
	}
}

// TunnelLocal reports whether a resolver of this kind sits inside the host or
// its overlay, which is what makes a lookup leave through the tunnel.
func (k Kind) TunnelLocal() bool {
	return k == KindLoopback || k == KindOverlay || k == KindFakeIP || k == KindPrivate
}

// DescribeServer renders a resolver server address for the report.
func DescribeServer(addr netip.Addr) string {
	return addr.String() + " (" + Classify(addr).String() + ")"
}

// IsEncryptedPort reports whether the resolver port carries an encrypted
// transport rather than cleartext DNS.
func IsEncryptedPort(port uint16) bool {
	return port == 443 || port == 853
}

// IsEncryptedFlag reports whether an scutil flag marks an encrypted resolver.
func IsEncryptedFlag(flag string) bool {
	return strings.Contains(strings.ToLower(flag), "encrypted")
}
