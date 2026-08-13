# PacketYeeter

This fork of PacketYeeter is a **collector-only** build.

The original upstream project included a separate analyzer service, ML, reputation scoring, and other higher-level detection components. This version removes that analyzer-centric architecture and keeps just the simpler local collector path.

For the original, fuller project, see:

- https://github.com/awlx/packetyeeter

## What this version does

The collector runs on a Linux host and uses **eBPF/XDP/TC** to inspect and control traffic close to the kernel.

Current responsibilities include:

- loading and attaching the PacketYeeter eBPF programs
- maintaining local blocklists in kernel maps
- enforcing IP blocks directly in XDP
- CIDR allowlist support
- per-CIDR policy handling
- TCP bad-flags filtering
- SYN-flood / incomplete-handshake tracking
- ICMP and UDP rate limiting
- local metrics export
- local incident logging
- HAProxy peer integration
- UNIX socket management interface for `yeetctl`

In short: this version is meant to be a **fast local enforcement daemon**, not a distributed collector/analyzer system.

## Included binaries

- `packetyeeter-collector` — main collector daemon
- `yeetctl` — small CLI for inspecting collector state

## Build

Typical build:

```bash
make
```

## Run

Example:

```bash
sudo ./packetyeeter-collector -i eth0
```

## `yeetctl`

`yeetctl` talks to the collector over its UNIX socket.

Examples:

```bash
sudo ./yeetctl list
sudo ./yeetctl whitelist
```

## Notes

- Linux is required for the collector.
- Root privileges or equivalent capabilities are required to load and attach eBPF programs.
- This README is intentionally minimal and describes this simplified fork, not the original multi-component design.

## License

See [`LICENSE`](LICENSE).
