#!/usr/bin/env python3
"""
Send lots of TCP SYNs without completing the handshake.

This is useful for exercising PacketYeeter's collector-side
incomplete-handshake autoblock logic.

Notes:
- Requires root/admin privileges to send raw packets.
- By default this script uses a fixed source IP chosen by the kernel unless
  you provide --src-ip and run in an environment where spoofing is allowed.
- If you do not spoof the source IP, your local host may receive SYN-ACKs and
  the kernel may reply with RSTs unless you firewall them off. For cleaner
  testing, either:
    1. run from another host/network namespace and drop outbound RSTs, or
    2. spoof a non-local source IP in a lab.
"""

import argparse
import random
import sys
import time

from scapy.all import IP, IPv6, TCP, send, conf  # type: ignore


def build_packet(dst_ip, dst_port, src_ip, src_port, ipv6):
    if ipv6:
        l3 = IPv6(dst=dst_ip, src=src_ip) if src_ip else IPv6(dst=dst_ip)
    else:
        l3 = IP(dst=dst_ip, src=src_ip) if src_ip else IP(dst=dst_ip)
    return l3 / TCP(dport=dst_port, sport=src_port, flags="S", seq=random.randint(0, 2**32 - 1))


def main():
    parser = argparse.ArgumentParser(description="Send many incomplete TCP handshakes (SYN only)")
    parser.add_argument("target", help="Target IPv4 or IPv6 address")
    parser.add_argument("--port", type=int, default=80, help="Target TCP port")
    parser.add_argument("--count", type=int, default=500, help="Total SYN packets to send")
    parser.add_argument("--pps", type=float, default=200.0, help="Approximate packets per second")
    parser.add_argument("--src-ip", default="", help="Optional spoofed source IP")
    parser.add_argument("--sport-start", type=int, default=10000, help="Starting source port")
    parser.add_argument("--ipv6", action="store_true", help="Use IPv6")
    args = parser.parse_args()

    conf.verb = 0

    if args.pps <= 0:
        print("--pps must be > 0", file=sys.stderr)
        sys.exit(2)

    delay = 1.0 / args.pps
    sent = 0

    print(
        f"Sending {args.count} SYNs to {args.target}:{args.port} "
        f"at about {args.pps:.1f} pps (ipv6={args.ipv6}, src_ip={args.src_ip or 'kernel-default'})"
    )

    start = time.time()
    for i in range(args.count):
        sport = args.sport_start + (i % 50000)
        pkt = build_packet(args.target, args.port, args.src_ip or None, sport, args.ipv6)
        send(pkt, verbose=False)
        sent += 1
        if sent % 50 == 0 or sent == args.count:
            elapsed = max(time.time() - start, 0.001)
            print(f"sent={sent} elapsed={elapsed:.2f}s rate={sent/elapsed:.1f}pps")
        time.sleep(delay)

    print("Done. If PacketYeeter is configured with -incomplete-handshake-threshold, check collector logs and /metrics.")


if __name__ == "__main__":
    main()
