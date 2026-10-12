# dns-verify

Answers four questions about the DNS of a macOS workstation, and nothing else:

1. Do you have your own DNS service?
2. Does all DNS go through the proxy?
3. Is there DNS hijacking?
4. Is there DNS leakage?

When none of the four is controlled, it says so instead of implying a result.

## Install

```sh
git clone https://github.com/fdaio/dns-verify
cd dns-verify
make build
```

The result is a single `dns-verify` binary with no configuration.

## Use

```sh
./dns-verify
```

The report opens with the overall verdict and the four answers, then shows the
measurements behind them.

```
DNS VERIFY
============================================================
Overall  [DNS is partly managed: 2 of 4 checks hold, 2 need attention.]

1. Do you have your own DNS service?
   [warn     ] Partly. Resolution runs through 100.101.255.254 (overlay), 223.5.5.5
   (public) cleartext :53, and 8.8.8.8 (public) cleartext :53. A public resolver
   answers in the clear for part of the namespace. 75 domains are routed to a
   dedicated resolver. No service has a hand-set server, so the resolver was not
   chosen here.
   -> Point every network service at the resolver your tunnel provides.
```

Each answer carries one of four states:

| State | Meaning |
|-------|---------|
| `good` | The control holds |
| `warn` | A control exists but does not cover everything |
| `unmanaged` | Nothing controls it |
| `unknown` | The measurement did not complete |

## How each question is measured

| Question | Measurement |
|----------|-------------|
| Own DNS service | The resolvers macOS applies, read from `scutil --dns`, grouped by address. `networksetup` tells whether a person set the server or the network handed it over. |
| All DNS through the proxy | Each resolver is asked which source address it sees (`whoami.cloudflare`). A resolver that answers from somewhere other than the tunnel exit sends queries outside the tunnel. The tunnel exit is measured with a plain HTTPS request to Cloudflare. |
| DNS hijacking | Random labels under the RFC 2606 domains `example.com`, `example.net`, and `example.org` are looked up. No honest resolver can return an address for them, so an answer is a rewritten one. |
| DNS leakage | The resolver source addresses are compared with the tunnel exit, and the network each address belongs to is looked up through Team Cymru over DNS. |

Supporting checks: cleartext DNS on port 53 over UDP and TCP, fake-IP answers in
`198.18.0.0/16`, DoH and DoT profiles in `/etc/resolver`, and IPv6 addresses that
sit on an interface the tunnel does not cover.

## What the report does not claim

A resolver that does not echo its source address cannot be cleared or blamed, so
the report names it as unmeasured rather than counting it as clean. An
unreachable resolver is reported as unmeasured, never as absent.

## Requirements

macOS. The tool reads the merged SystemConfiguration state, which no other
platform exposes the same way. Running it elsewhere exits with an error.

## Development

```sh
make build   # build the binary
make test    # run the tests
make lint    # run golangci-lint
make fmt     # format the sources
```

The parsing and the verdict rules are separate from the network calls, so both
are tested without a network.

## License

MIT