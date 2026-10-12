# dns-verify

Reports the DNS posture of a macOS or Linux workstation in one screen: a score
out of ten, four verdicts, and what to do next.

```
$ dns-verify
⠹ ██████████░░░░░░░░░░ 4/8  probing for hijacked answers
DNS VERIFY                                        8/10  PARTLY MANAGED

1  Own DNS .............      warn  a public resolver answers in the clear; no service has a hand-set server
2  All DNS via proxy ...      warn  cleartext DNS completes to a public resolver on port 53
3  DNS hijacking .......      good  none found in 18 probes
4  DNS leakage .........      good  no leak from 1 resolver

FIX FIRST
  ! 1. Point every network service at the resolver your tunnel provides
  ! 2. Block outbound port 53 so only the tunnel resolver stays reachable
```

macOS and Linux only. Each system keeps its resolver configuration somewhere
different, so the check reads what that system actually applies rather than
assuming one layout.

## Install

Pick your system and architecture: `arm64` on Apple silicon and most modern
CPUs, `amd64` on Intel. The archive holds a single binary.

```sh
OS=darwin                                    # darwin or linux
ARCH=arm64
curl -fsSL "https://github.com/fdaio/dns-verify/releases/latest/download/dns-verify_${OS}_${ARCH}.tar.gz" | tar xz
sudo install -m 0755 dns-verify /usr/local/bin/
dns-verify --version
```

From source, `git clone https://github.com/fdaio/dns-verify && cd dns-verify && make build`.

## Uninstall

The check only reads. It never changes a resolver, a route or any setting, so
removing it leaves the machine exactly as it was.

```sh
sudo rm /usr/local/bin/dns-verify
rm -f dns-verify_darwin_*.tar.gz dns-verify_linux_*.tar.gz
```

## Flags

| Flag | Effect |
|------|--------|
| `--version` | Print the release the binary was built from |
| `-v` | Add the measurements behind each verdict |
| `--fail-under N` | Exit 1 when the score is below N, from 0 to 10 |

A plain run always exits 0. The threshold is only there to gate a pipeline.

## The four questions

| Label | Question |
|-------|----------|
| `Own DNS` | Do you have your own DNS service? |
| `All DNS via proxy` | Does all DNS go through the proxy? |
| `DNS hijacking` | Is there DNS hijacking? |
| `DNS leakage` | Is there DNS leakage? |

When none of the four is controlled, the grade reads `NOT MANAGED` rather than
implying a result. Ten points, 2.5 per question:

| State | Points | Meaning |
|-------|--------|---------|
| `good` | 2.5 | The control holds |
| `warn` | 1.5 | A control exists but does not cover everything |
| `unmanaged` | 0 | Nothing controls it |
| `unknown` | 0 | The measurement did not complete |

An unmeasured question earns nothing, because it has not been shown to be safe,
and the headline counts how many were left unmeasured.

## How it measures

| Question | Measurement |
|----------|-------------|
| Own DNS | The resolvers this system applies: SystemConfiguration on macOS, and `/etc/resolv.conf` plus the stack behind it on Linux. Whether a person set the resolver or the network handed it over is read from the source. |
| Via proxy | Each resolver is asked which source address it sees. One answering from outside the tunnel exit sends queries outside the tunnel. The exit is measured with a plain HTTPS request to Cloudflare. |
| Hijacking | Random labels under the RFC 2606 domains. No honest resolver can answer them, so any address returned is a rewritten one. |
| Leakage | Those source addresses are compared with the tunnel exit, and each one's network is looked up through Team Cymru over DNS. |

Supporting probes: cleartext DNS on port 53 over UDP and TCP, fake-IP answers in
`198.18.0.0/16`, encrypted resolvers, and IPv6 on an interface the tunnel does
not cover. A resolver that cannot echo its source address is named as unmeasured,
never counted as clean. A fix carries a runnable command only when the tool can
name both the service and the address to write, and the command is the one that
system uses.

## Development

`make build`, `make test`, `make lint`, `make fmt`. The parsing, the scoring and
the exit code are separate from the network calls, so they are tested without one.

## License

MIT