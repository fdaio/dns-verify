package sysdns

import (
	"net/netip"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		addr string
		want Kind
	}{
		{"127.0.0.1", KindLoopback},
		{"::1", KindLoopback},
		{"100.101.255.254", KindOverlay},
		{"100.64.0.1", KindOverlay},
		{"198.18.0.1", KindFakeIP},
		{"192.168.1.1", KindPrivate},
		{"10.0.0.1", KindPrivate},
		{"169.254.10.1", KindPrivate},
		{"1.1.1.1", KindPublic},
		{"8.8.8.8", KindPublic},
		{"223.5.5.5", KindPublic},
	}
	for _, c := range cases {
		if got := Classify(netip.MustParseAddr(c.addr)); got != c.want {
			t.Errorf("Classify(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
	if got := Classify(netip.Addr{}); got != KindUnknown {
		t.Errorf("Classify(invalid) = %v, want %v", got, KindUnknown)
	}
}

// A public address just above the overlay range must not be read as an overlay
// resolver, because that would clear a resolver the tunnel does not own.
func TestClassifyBoundaryAroundOverlayRange(t *testing.T) {
	if got := Classify(netip.MustParseAddr("100.63.255.255")); got != KindPublic {
		t.Errorf("100.63.255.255 = %v, want %v", got, KindPublic)
	}
	if got := Classify(netip.MustParseAddr("100.128.0.0")); got != KindPublic {
		t.Errorf("100.128.0.0 = %v, want %v", got, KindPublic)
	}
}

func TestTunnelLocal(t *testing.T) {
	local := []Kind{KindLoopback, KindOverlay, KindFakeIP, KindPrivate}
	for _, k := range local {
		if !k.TunnelLocal() {
			t.Errorf("%v should be tunnel local", k)
		}
	}
	for _, k := range []Kind{KindPublic, KindUnknown} {
		if k.TunnelLocal() {
			t.Errorf("%v should not be tunnel local", k)
		}
	}
}

func TestIsFakeIP(t *testing.T) {
	fake := []string{"198.18.0.1", "198.18.7.9", "198.18.255.254"}
	for _, addr := range fake {
		if !IsFakeIP(netip.MustParseAddr(addr)) {
			t.Errorf("%s should be fake-ip", addr)
		}
	}
	for _, addr := range []string{"198.17.255.255", "198.19.0.1", "172.66.147.243"} {
		if IsFakeIP(netip.MustParseAddr(addr)) {
			t.Errorf("%s should not be fake-ip", addr)
		}
	}
}

func TestIsEncryptedPort(t *testing.T) {
	for _, port := range []uint16{443, 853} {
		if !IsEncryptedPort(port) {
			t.Errorf("port %d should be encrypted", port)
		}
	}
	for _, port := range []uint16{53, 5353, 80} {
		if IsEncryptedPort(port) {
			t.Errorf("port %d should not be encrypted", port)
		}
	}
}

func TestIsTunnelInterface(t *testing.T) {
	for _, name := range []string{"utun0", "utun3", "ppp0", "ipsec0", "gif0"} {
		if !isTunnelInterface(name) {
			t.Errorf("%s should be a tunnel interface", name)
		}
	}
	for _, name := range []string{"en0", "en10", "bridge0", "lo0"} {
		if isTunnelInterface(name) {
			t.Errorf("%s should not be a tunnel interface", name)
		}
	}
}
