# dns-verify

Reports the DNS posture of a macOS workstation in one screen: a score out of
ten, four verdicts, and what to do next.

```
$ dns-verify
DNS VERIFY                                        8/10  PARTLY MANAGED

1  Own DNS .............      warn  a public resolver answers in the clear; no service has a hand-set server
2  All DNS via proxy ...      warn  cleartext DNS completes to a public resolver on port 53
3  DNS hijacking .......      good  none found in 18 probes
4  DNS leakage .........      good  no leak from 1 resolver

FIX FIRST
  1. Point every network service at the resolver your tunnel provides
  2. Block outbound port 53 so only the tunnel resolver stays reachable

Run with -v for the measurements behind these verdicts.
```

## The four questions

| Label | Question |
|-------|----------|
| `Own DNS` | Do you have your own DNS service? |
| `All DNS via proxy` | Does all DNS go through the proxy? |
| `DNS hijacking` | Is there DNS hijacking? |
| `DNS leakage` | Is there DNS leakage? |

When none of the four is controlled, the grade reads `NOT MANAGED` instead of
implying a result.

## Terminal output

While the check runs, a single line shows what it is doing:

```
⠹ ████████░░░░░░░░░░  asking resolvers for their source address  4/9
```

The bar covers the whole run, not the current stage, so it only ever moves
forward. The bar has a fixed width and the stage name starts on a fixed column,
so only the text at the end of the line changes as the run goes on.

The line is erased before the report prints, so nothing is left behind when the
run ends, fails or is interrupted.

In a terminal the verdict states are coloured: `good` green, `warn` yellow,
`unmanaged` red, and `unknown` grey. The score carries the colour of its grade.
Nothing else is coloured, so the colour means severity and nothing more.

Both colour and the progress line need a terminal, and both are off otherwise:

| Stream | Colour | Progress |
|--------|--------|----------|
| Terminal | on | on |
| Redirected to a file | off | off |
| In a pipeline | off | off |
| `NO_COLOR=1` in a terminal | off | on |
| `TERM=dumb` in a terminal | off | off |

A stream that cannot show them receives no escape sequence at all, so a report
redirected to a file stays byte for byte the plain text.

## Flags

| Flag | Effect |
|------|--------|
| `-v` | Add the measurements behind each verdict |
| `--fail-under N` | Exit 1 when the score is below N (0 to 10) |

A plain run always exits 0. The threshold is only there for a gate.

## Score

The ten points are split evenly over the four questions, 2.5 each. Every
verdict uses one of four states, and the state determines both the label on the
line and the points it earns.

| State | Points | Meaning |
|-------|--------|---------|
| `good` | 2.5 | The control holds |
| `warn` | 1.5 | A control exists but does not cover everything |
| `unmanaged` | 0 | Nothing controls it |
| `unknown` | 0 | The measurement did not complete |

An unmeasured question earns nothing, because it has not been shown to be safe.
The headline counts how many were left unmeasured.

## How each question is measured

| Question | Measurement |
|----------|-------------|
| Own DNS | The resolvers macOS applies, read from `scutil --dns`, grouped by address. `networksetup` tells whether a person set the server or the network handed it over. |
| All DNS via proxy | Each resolver is asked which source address it sees (`whoami.cloudflare`, retried because the query travels over UDP). A resolver that answers from somewhere other than the tunnel exit sends queries outside the tunnel. The exit is measured with a plain HTTPS request to Cloudflare. |
| DNS hijacking | Random labels under the RFC 2606 domains `example.com`, `example.net`, and `example.org` are looked up. No honest resolver can return an address for them, so an answer is a rewritten one. |
| DNS leakage | The resolver source addresses are compared with the tunnel exit, and the network each address belongs to is looked up through Team Cymru over DNS. |

Supporting probes: cleartext DNS on port 53 over UDP and TCP, fake-IP answers in
`198.18.0.0/16`, DoH and DoT profiles in `/etc/resolver`, and IPv6 addresses that
sit on an interface the tunnel does not cover.

## What the report does not claim

A resolver that does not echo its source address cannot be cleared or blamed, so
the report names it as unmeasured rather than counting it as clean. A fix gets a
runnable command only when the tool can name both the network service and the
address to write, because a command with a placeholder is easier to run wrong
than to read.

## Install

```sh
git clone https://github.com/fdaio/dns-verify
cd dns-verify
make build
```

The result is a single `dns-verify` binary.

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

The parsing, the scoring and the exit code are separate from the network calls,
so all of them are tested without a network.

## License

MIT