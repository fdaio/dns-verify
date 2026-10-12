package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// traceURL is the endpoint that reports the source address it saw. It is a
// plain HTTPS request, so the result is the tunnel exit when one is in use.
const traceURL = "https://www.cloudflare.com/cdn-cgi/trace"

// Egress is the source address the internet sees for ordinary traffic.
type Egress struct {
	// Addr is the observed source address.
	Addr netip.Addr
	// Site names the endpoint that reported it.
	Site string
}

// egressAttempts is how many times the trace request is sent. Every other
// verdict is compared against the exit address, so one refused connection must
// not leave the run unable to say anything about the machine.
const egressAttempts = 3

// EgressAddr determines the source address of ordinary HTTPS traffic.
//
// The request must follow the proxy that macOS applies, otherwise the measured
// address is the tunnel exit while the queries under test still leave directly,
// and the comparison between the two is meaningless.
func EgressAddr(ctx context.Context) (Egress, error) {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: defaultTimeout}).DialContext,
		TLSHandshakeTimeout:   defaultTimeout,
		ResponseHeaderTimeout: defaultTimeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var err error
	for range egressAttempts {
		addr, attemptErr := egressOnce(ctx, client)
		if attemptErr == nil {
			return addr, nil
		}
		err = attemptErr
	}
	return Egress{}, err
}

func egressOnce(ctx context.Context, client *http.Client) (Egress, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
	if err != nil {
		return Egress{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Egress{}, fmt.Errorf("egress trace: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return Egress{}, fmt.Errorf("egress trace: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Egress{}, fmt.Errorf("egress trace: %s", resp.Status)
	}

	for line := range strings.SplitSeq(string(body), "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "ip=")
		if !ok {
			continue
		}
		if addr, parsed := parseIPField(value); parsed {
			return Egress{Addr: addr, Site: "cloudflare.com"}, nil
		}
	}
	return Egress{}, fmt.Errorf("egress trace: no address in response")
}
