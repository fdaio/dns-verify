// Package render prints an analysed run as a text report.
package render

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/fdaio/dns-verify/internal/analyze"
	"github.com/fdaio/dns-verify/internal/sysdns"
)

// statusWidth is the column width of the verdict label.
const statusWidth = 9

// Report writes the full text report.
func Report(w io.Writer, r analyze.Report) error {
	writeHeader(w, r)
	writeAnswers(w, r)
	writeDetails(w, r)
	return nil
}

func writeHeader(w io.Writer, r analyze.Report) {
	fmt.Fprintln(w, "DNS VERIFY")
	fmt.Fprintln(w, strings.Repeat("=", 60))
	fmt.Fprintf(w, "Overall  [%s]\n", r.Overall())
	fmt.Fprintln(w)
}

func writeAnswers(w io.Writer, r analyze.Report) {
	for i, a := range r.Answers {
		fmt.Fprintf(w, "%d. %s\n", i+1, a.Question)
		fmt.Fprintf(w, "   [%s] %s\n", pad(a.State.String()), a.Summary)
		if a.Advice != "" {
			fmt.Fprintf(w, "   -> %s\n", a.Advice)
		}
		fmt.Fprintln(w)
	}
}

func writeDetails(w io.Writer, r analyze.Report) {
	fmt.Fprintln(w, "DETAILS")
	fmt.Fprintln(w, strings.Repeat("-", 60))

	f := r.Facts

	fmt.Fprintln(w, "Resolvers in effect")
	if len(f.Resolvers) == 0 {
		fmt.Fprintln(w, "  none found")
	}
	for _, v := range f.Resolvers {
		fmt.Fprintf(w, "  %-16s %-9s port %-5d %s\n",
			v.Addr, v.Kind, v.Port, resolverNotes(v))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Tunnel exit")
	if f.Egress == nil {
		fmt.Fprintln(w, "  not measured")
	} else {
		fmt.Fprintf(w, "  %s via %s\n", f.Egress.Addr, f.Egress.Site)
		if f.EgressOrigin != nil {
			fmt.Fprintf(w, "  network %s %s %s\n",
				f.EgressOrigin, f.EgressOrigin.Country, f.EgressOrigin.Prefix)
		}
	}

	if len(f.EncryptedProfiles) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Encrypted profiles in %s\n", sysdns.ResolverDir)
		for _, p := range f.EncryptedProfiles {
			fmt.Fprintf(w, "  %s\n", p)
		}
	}

	if f.SplitScopedDomains > 0 {
		fmt.Fprintf(w, "\nSplit-DNS  %d domains routed to a dedicated resolver\n", f.SplitScopedDomains)
	}
	fmt.Fprintf(w, "Services   %d of %d have a hand-set DNS server\n",
		f.ExplicitServices, f.TotalServices)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Transport")
	fmt.Fprintf(w, "  cleartext UDP  %s\n", yesNo(f.PlaintextUDP))
	fmt.Fprintf(w, "  cleartext TCP  %s\n", yesNo(f.PlaintextTCP))
	fmt.Fprintf(w, "  fake-ip        %s\n", yesNo(fakeIP(f)))
	if len(f.IPv6Bypass) > 0 {
		fmt.Fprintf(w, "  IPv6 outside the tunnel  %s\n", strings.Join(f.IPv6Bypass, ", "))
	} else {
		fmt.Fprintln(w, "  IPv6 outside the tunnel  no")
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Hijack probe")
	if len(f.Hijack.Probed) == 0 {
		fmt.Fprintln(w, "  did not complete")
	} else {
		fmt.Fprintf(w, "  %d unresolvable names probed, %d rewritten into addresses\n",
			len(f.Hijack.Probed), len(f.Hijack.Answers))
		for label, addrs := range f.Hijack.Answers {
			fmt.Fprintf(w, "    %s -> %s\n", label, joinAddrs(addrs))
		}
	}
}

// resolverNotes lists the facts about one resolver that the report shows.
func resolverNotes(v analyze.ResolverView) string {
	var notes []string
	if !v.Reachable {
		notes = append(notes, "not reachable")
	}
	if v.Encrypted() {
		notes = append(notes, "encrypted transport")
	}
	if v.FakeIP {
		notes = append(notes, "hands out fake addresses")
	}
	if v.Explicit {
		notes = append(notes, "hand-set on a service")
	}
	if len(v.ServesDomains) > 0 {
		notes = append(notes, fmt.Sprintf("serves %d domains", len(v.ServesDomains)))
	}
	if v.EchoAddr.IsValid() {
		notes = append(notes, "answers from "+v.EchoAddr.String())
	} else if v.EchoErr != nil {
		notes = append(notes, "did not report a source address")
	}
	if v.UpstreamAddr.IsValid() {
		notes = append(notes, "forwarded to "+v.UpstreamAddr.String())
	}
	if len(notes) == 0 {
		return "-"
	}
	return strings.Join(notes, ", ")
}

func fakeIP(f analyze.Facts) bool {
	for _, v := range f.Resolvers {
		if v.FakeIP {
			return true
		}
	}
	return false
}

func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// pad right-aligns the verdict label in a fixed column.
func pad(s string) string {
	if len(s) >= statusWidth {
		return s
	}
	return s + strings.Repeat(" ", statusWidth-len(s))
}
