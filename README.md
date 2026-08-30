# Tricep

[![Build](https://github.com/ausimian/tricep/actions/workflows/build.yaml/badge.svg)](https://github.com/ausimian/tricep/actions/workflows/build.yaml)
[![Coverage Status](https://coveralls.io/repos/github/ausimian/tricep/badge.svg?branch=main)](https://coveralls.io/github/ausimian/tricep?branch=main)

A user-mode IPv6/TCP stack written in Elixir.

Tricep connects to TUN devices (or other transports) via a Link abstraction and implements the TCP/IP protocol in user space. This allows for custom networking stacks, testing, and experimentation without kernel modifications.

**This project is under early development and is not yet suitable for production use.**

## Features

- IPv6 support
- TCP client and server connections (handshake, data transfer)
- TUN device integration via [Tundra](https://hex.pm/packages/tundra)
- Pluggable link layer abstraction

## Requirements

- Elixir 1.15+
- Linux (macOS support planned)
- Root or `CAP_NET_ADMIN` for TUN device creation

## Development

Install dependencies and run the complete verification suite before committing:

```console
mix deps.get
mix precommit
```

The preferred development toolchain is pinned in `.tool-versions` at Elixir
1.19.5 / OTP 28.3. This is also the canonical CI coverage toolchain, so local
and gated coverage use the same compiler. Both mise and asdf can install these
versions from that file.

`mix precommit` compiles with warnings treated as errors, verifies that the
dependency lockfile has no unused entries or unstaged changes, checks
formatting, runs Credo in strict mode, and runs the test suite with the
configured minimum coverage threshold. Stage an intentional `mix.lock` update
before running the gate so it can verify the update will be committed.

`mix precommit_checks` is the compile-and-lint subset used internally by
non-canonical CI matrix jobs; it is not a replacement for the complete local
gate. CI enforces the 80% coverage threshold with `mix precommit` on the
explicitly flagged coverage job, then runs the suite again to publish that
job's coverage to Coveralls. That canonical job also runs `mix test --only
fin_ack_rto` for the two-test FIN+ACK retransmission pair without enabling
integration or inherited slow tests. Other supported Elixir/OTP jobs pair
`mix precommit_checks` with plain `mix test` so compiler-specific coverage line
attribution cannot make legacy toolchains fail the canonical coverage gate.

## Usage

```elixir
# Create a TUN link
{:ok, _link} = Tricep.Link.new(
  ifaddr: "fd00::1",
  dstaddr: "fd00::2",
  netmask: "ffff:ffff:ffff:ffff::",
  mtu: 1500
)

# Open a TCP socket and connect
{:ok, sock} = Tricep.open(:inet6, :stream, :tcp)
:ok = Tricep.connect(sock, %{family: :inet6, addr: {0xfd00, 0, 0, 0, 0, 0, 0, 1}, port: 8080})

# Or listen for inbound TCP connections
{:ok, listener} = Tricep.open(:inet6, :stream, :tcp)
:ok = Tricep.bind(listener, %{family: :inet6, addr: "fd00::2", port: 8080})
:ok = Tricep.listen(listener)
{:ok, client} = Tricep.accept(listener)
```
