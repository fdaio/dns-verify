// Package probe measures what the DNS path of this machine actually does.
//
// Every measurement queries through the resolver that macOS applies to the
// process, not through a resolver the tool picks. That is the only way to
// observe the path a normal application takes.
package probe

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const defaultTimeout = 5 * time.Second

// Resolver is one nameserver the probe can send queries to.
type Resolver struct {
	Addr netip.Addr
	Port uint16
}

// String renders the resolver as an address:port pair.
func (r Resolver) String() string {
	port := r.Port
	if port == 0 {
		port = 53
	}
	return net.JoinHostPort(r.Addr.String(), strconv.Itoa(int(port)))
}

func (r Resolver) client(network string) *dns.Client {
	return &dns.Client{
		Net:     network,
		Timeout: defaultTimeout,
	}
}

// ErrNoAnswer reports that the query reached the resolver but carried no record.
var ErrNoAnswer = errors.New("no answer")

// exchange sends one query and returns the response message.
func (r Resolver) exchange(ctx context.Context, network string, msg *dns.Msg) (*dns.Msg, error) {
	c := r.client(network)
	resp, _, err := c.ExchangeContext(ctx, msg, r.String())
	if err != nil {
		return nil, fmt.Errorf("%s via %s: %w", msg.Question[0].Name, r, err)
	}
	return resp, nil
}

// newMsg builds a recursive query for one name.
func newMsg(name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	return msg
}

// firstTXT returns the first TXT answer that parses as an address.
func firstTXT(resp *dns.Msg) (netip.Addr, bool) {
	for _, record := range resp.Answer {
		txt, ok := record.(*dns.TXT)
		if !ok {
			continue
		}
		for _, field := range txt.Txt {
			if addr, ok := parseIPField(field); ok {
				return addr, true
			}
		}
	}
	return netip.Addr{}, false
}

// ResolverEcho asks a resolver which source address it sees. The resolver
// answers, so the value is where the resolver's own path to the internet
// starts, which is the path every lookup through it takes.
func ResolverEcho(ctx context.Context, r Resolver) (netip.Addr, error) {
	msg := newMsg("whoami.cloudflare", dns.TypeTXT)
	msg.Question[0].Qclass = dns.ClassCHAOS

	resp, err := r.exchange(ctx, "udp", msg)
	if err != nil {
		return netip.Addr{}, err
	}
	if addr, ok := firstTXT(resp); ok {
		return addr, nil
	}
	return netip.Addr{}, ErrNoAnswer
}

// RecursiveEcho asks an authoritative lookup service which resolver performed
// the recursion. A local forwarder answers with its own upstream resolver, so
// the result names the machine that really resolved the name.
func RecursiveEcho(ctx context.Context, r Resolver) (netip.Addr, error) {
	resp, err := r.exchange(ctx, "udp", newMsg("o-o.myaddr.l.google.com", dns.TypeTXT))
	if err != nil {
		return netip.Addr{}, err
	}
	if addr, ok := firstTXT(resp); ok {
		return addr, nil
	}
	return netip.Addr{}, ErrNoAnswer
}

// PlaintextReachable reports whether cleartext DNS to the resolver completes on
// the given transport.
func PlaintextReachable(ctx context.Context, r Resolver, network string) error {
	resp, err := r.exchange(ctx, network, newMsg("example.com", dns.TypeA))
	if err != nil {
		return err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("%s via %s: %s", resp.Question[0].Name, r, dns.RcodeToString[resp.Rcode])
	}
	return nil
}

// HijackResult reports what a resolver did with a name that cannot exist.
type HijackResult struct {
	// Probed lists the labels that were looked up.
	Probed []string
	// Answers maps a probed label to the addresses returned for it.
	Answers map[string][]netip.Addr
}

// Hijacked reports whether any unresolvable name produced an address record.
func (h HijackResult) Hijacked() bool {
	return len(h.Answers) > 0
}

// hijackDomains are reserved by RFC 2606 for documentation. No legitimate
// resolver can return an address for a random label under them, so an answer is
// a rewritten response.
var hijackDomains = []string{"example.com", "example.net", "example.org"}

// Hijack sends lookups for random labels under reserved domains. A resolver that
// rewrites unknown names returns an address for them.
func Hijack(ctx context.Context, r Resolver, count int) (HijackResult, error) {
	result := HijackResult{Answers: make(map[string][]netip.Addr)}
	for _, domain := range hijackDomains {
		for i := 0; i < count; i++ {
			label := randomLabel() + "." + domain

			resp, err := r.exchange(ctx, "udp", newMsg(label, dns.TypeA))
			if err != nil {
				continue
			}
			result.Probed = append(result.Probed, label)
			for _, record := range resp.Answer {
				switch rr := record.(type) {
				case *dns.A:
					if addr, ok := netip.AddrFromSlice(rr.A.To4()); ok {
						result.Answers[label] = append(result.Answers[label], addr)
					}
				case *dns.CNAME:
					if target, err := netip.ParseAddr(strings.TrimSuffix(rr.Target, ".")); err == nil {
						result.Answers[label] = append(result.Answers[label], target)
					}
				}
			}
		}
	}
	if len(result.Probed) == 0 {
		return result, fmt.Errorf("no hijack probe completed against %s", r)
	}
	return result, nil
}

// ResolvedAddrs looks a name up through the resolver and returns its addresses.
// The lookup proves the resolver can answer at all and exposes fake-IP answers.
func ResolvedAddrs(ctx context.Context, r Resolver, name string) ([]netip.Addr, error) {
	var out []netip.Addr
	resp, err := r.exchange(ctx, "udp", newMsg(name, dns.TypeA))
	if err != nil {
		return nil, err
	}
	for _, record := range resp.Answer {
		a, ok := record.(*dns.A)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(a.A.To4()); ok {
			out = append(out, addr)
		}
	}
	return out, nil
}

// randomLabel returns a hex label long enough that no zone can hold it.
func randomLabel() string {
	const bytes = 16
	buf := make([]byte, bytes)
	for i := range buf {
		buf[i] = byte(rand.IntN(256))
	}
	const hexDigits = "0123456789abcdef"
	var sb strings.Builder
	sb.Grow(bytes * 2)
	for _, b := range buf {
		sb.WriteByte(hexDigits[b>>4])
		sb.WriteByte(hexDigits[b&0x0f])
	}
	return sb.String()
}

// parseIPField extracts an address from a TXT answer. The lookup services pad
// their answers with a client-subnet line, which is not an address.
func parseIPField(field string) (netip.Addr, bool) {
	field = strings.Trim(strings.TrimSpace(field), `"`)
	if field == "" || strings.Contains(field, " ") {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(field)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
