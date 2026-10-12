package probe

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Team Cymru answers origin queries over plain DNS, which keeps the lookup
// inside the resolver path the report is measuring and needs no API key.
const (
	originV4Format = "%s.origin.asn.cymru.com"
	originV6Format = "%s.origin6.asn.cymru.com"
)

// Origin describes the network an address belongs to.
type Origin struct {
	// ASN is the autonomous system number.
	ASN uint32
	// Prefix is the announced block the address falls in.
	Prefix string
	// Country is the registry country code.
	Country string
}

// String renders the origin as its AS number.
func (o Origin) String() string {
	return "AS" + strconv.FormatUint(uint64(o.ASN), 10)
}

// OriginOf looks up the announced origin of an address through the resolver
// under test.
func OriginOf(ctx context.Context, r Resolver, addr netip.Addr) (Origin, error) {
	resp, err := r.exchange(ctx, "udp", newMsg(originQueryName(addr), dns.TypeTXT))
	if err != nil {
		return Origin{}, err
	}
	for _, record := range resp.Answer {
		txt, ok := record.(*dns.TXT)
		if !ok {
			continue
		}
		for _, field := range txt.Txt {
			if origin, ok := parseOrigin(field); ok {
				return origin, nil
			}
		}
	}
	return Origin{}, ErrNoAnswer
}

// originQueryName writes the address in the reversed nibble form that the
// origin service expects. IPv4 and IPv6 use different service names.
func originQueryName(addr netip.Addr) string {
	if addr.Is4() {
		raw := addr.As4()
		return fmt.Sprintf(originV4Format, reverseNibbles(raw[:]))
	}
	raw := addr.As16()
	return fmt.Sprintf(originV6Format, reverseNibbles(raw[:]))
}

// parseOrigin reads the "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11" answer.
func parseOrigin(text string) (Origin, bool) {
	fields := strings.Split(strings.Trim(strings.TrimSpace(text), `"`), "|")
	if len(fields) < 3 {
		return Origin{}, false
	}
	asn, err := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 32)
	if err != nil {
		return Origin{}, false
	}
	country := strings.TrimSpace(fields[2])
	if country == "" || country == "ZZ" {
		return Origin{}, false
	}
	return Origin{
		ASN:     uint32(asn),
		Prefix:  strings.TrimSpace(fields[1]),
		Country: country,
	}, true
}

// reverseNibbles writes an address as reversed nibbles, the form the origin
// service expects.
func reverseNibbles(raw []byte) string {
	var sb strings.Builder
	sb.Grow(len(raw) * 2)
	for i := len(raw) - 1; i >= 0; i-- {
		sb.WriteByte(hexDigit(raw[i] >> 4))
		sb.WriteByte(hexDigit(raw[i] & 0x0f))
	}
	return sb.String()
}

func hexDigit(nibble byte) byte {
	const digits = "0123456789abcdef"
	return digits[nibble&0x0f]
}
