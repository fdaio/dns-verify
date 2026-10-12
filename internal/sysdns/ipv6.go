package sysdns

import (
	"net"
	"net/netip"
	"strings"
)

// tunnelPrefixes name the interface families that carry a tunnel. Their IPv6
// addresses are covered by that tunnel, so they cannot bypass it.
var tunnelPrefixes = []string{"utun", "utap", "ppp", "ipsec", "gif", "stf", "tun", "tap"}

// IPv6Bypass lists the global unicast IPv6 addresses that a tunnel does not
// cover. A link-local address cannot leave the link, so it cannot leak a query.
//
// An address that survives this test gives a lookup a second way out that no
// IPv4 tunnel rule covers.
func IPv6Bypass() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || isTunnelInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addrs {
			addr, ok := parseInterfaceAddr(raw)
			if !ok {
				continue
			}
			if addr.Is4() || addr.Is4In6() || addr.IsLinkLocalUnicast() {
				continue
			}
			if !addr.IsGlobalUnicast() {
				continue
			}
			out = append(out, addr.String()+" ("+iface.Name+")")
		}
	}
	return out, nil
}

func isTunnelInterface(name string) bool {
	for _, prefix := range tunnelPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// parseInterfaceAddr converts the "2001:db8::1/64" form that net reports.
func parseInterfaceAddr(raw net.Addr) (netip.Addr, bool) {
	value, _, _ := strings.Cut(raw.String(), "/")
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
