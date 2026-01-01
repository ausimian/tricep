# Tricep

A user-mode IPv6/TCP stack written in Elixir.

Tricep connects to TUN devices (or other transports) via a Link abstraction and implements the TCP/IP protocol in user space. This allows for custom networking stacks, testing, and experimentation without kernel modifications.

**This project is under early development and is not yet suitable for production use.**

## Features

- IPv6 support
- TCP client connections (handshake, data transfer)
- TUN device integration via [Tundra](https://hex.pm/packages/tundra)
- Pluggable link layer abstraction

## Requirements

- Elixir 1.15+
- Linux (macOS support planned)
- Root or `CAP_NET_ADMIN` for TUN device creation

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
```

