#!/usr/bin/env python3
import argparse
import socket
import sys
import time


def parse_args():
    p = argparse.ArgumentParser(
        description="Send UDP packets at a target PPS for PacketYeeter validation"
    )
    p.add_argument("host", help="Destination host or IP")
    p.add_argument("port", type=int, help="Destination UDP port")
    p.add_argument("--pps", type=float, default=1000.0, help="Target packets per second")
    p.add_argument("--duration", type=float, default=10.0, help="How long to send traffic, in seconds")
    p.add_argument("--size", type=int, default=64, help="UDP payload size in bytes")
    p.add_argument("--bind", default="", help="Optional source IP to bind from")
    p.add_argument("--report-interval", type=float, default=1.0, help="Progress report interval in seconds")
    p.add_argument(
        "--tick-ms",
        type=float,
        default=10.0,
        help="Pacing tick in milliseconds; each tick sends a batch back-to-back",
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=0,
        help="Optional cap per inner send burst; 0 means send full tick batch",
    )
    return p.parse_args()


def make_payload(size: int) -> bytes:
    if size <= 0:
        return b""
    pattern = b"PACKETYEETER-UDP-TEST-"
    repeats = (size // len(pattern)) + 1
    return (pattern * repeats)[:size]


def send_burst(sock, payload: bytes, addr, count: int, batch_size: int) -> int:
    sent = 0

    if count <= 0:
        return 0

    if batch_size <= 0 or batch_size >= count:
        for _ in range(count):
            sock.sendto(payload, addr)
        return count

    remaining = count
    while remaining > 0:
        chunk = min(remaining, batch_size)
        for _ in range(chunk):
            sock.sendto(payload, addr)
        sent += chunk
        remaining -= chunk

    return sent


def main():
    args = parse_args()

    if args.pps <= 0:
        print("--pps must be > 0", file=sys.stderr)
        return 2
    if args.duration <= 0:
        print("--duration must be > 0", file=sys.stderr)
        return 2
    if args.size < 0:
        print("--size must be >= 0", file=sys.stderr)
        return 2
    if args.report_interval <= 0:
        print("--report-interval must be > 0", file=sys.stderr)
        return 2
    if args.tick_ms <= 0:
        print("--tick-ms must be > 0", file=sys.stderr)
        return 2
    if args.batch_size < 0:
        print("--batch-size must be >= 0", file=sys.stderr)
        return 2

    payload = make_payload(args.size)
    tick_seconds = args.tick_ms / 1000.0

    try:
        addrinfo = socket.getaddrinfo(args.host, args.port, type=socket.SOCK_DGRAM)[0]
        family = addrinfo[0]
        addr = addrinfo[4]
    except socket.gaierror as e:
        print(f"failed to resolve destination: {e}", file=sys.stderr)
        return 2

    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if args.bind:
            bind_port = 0
            if family == socket.AF_INET6:
                sock.bind((args.bind, bind_port, 0, 0))
            else:
                sock.bind((args.bind, bind_port))

        start = time.perf_counter()
        end = start + args.duration
        next_report = start + args.report_interval
        next_tick = start

        sent = 0
        report_sent = 0

        print(
            f"Sending UDP to {args.host}:{args.port} at target {args.pps:.2f} pps "
            f"for {args.duration:.2f}s with payload {len(payload)} bytes"
        )
        print(f"tick_ms={args.tick_ms:.3f} batch_size={args.batch_size}")
        if args.bind:
            print(f"Bound source IP: {args.bind}")

        while True:
            now = time.perf_counter()
            if now >= end:
                break

            if now < next_tick:
                sleep_for = next_tick - now
                if sleep_for > 0:
                    time.sleep(sleep_for)
                continue

            elapsed = now - start
            target_sent = int(elapsed * args.pps)
            to_send = target_sent - sent

            if to_send <= 0:
                to_send = max(1, int(args.pps * tick_seconds))

            actually_sent = send_burst(sock, payload, addr, to_send, args.batch_size)
            sent += actually_sent
            report_sent += actually_sent

            next_tick += tick_seconds
            now = time.perf_counter()

            if now >= next_report:
                elapsed = now - start
                actual_interval = args.report_interval
                actual_pps = report_sent / actual_interval
                print(
                    f"elapsed={elapsed:.2f}s sent={sent} interval_pps={actual_pps:.2f}"
                )
                report_sent = 0
                while next_report <= now:
                    next_report += args.report_interval

        total_elapsed = time.perf_counter() - start
        avg_pps = sent / total_elapsed if total_elapsed > 0 else 0.0
        print(f"Done: sent={sent} elapsed={total_elapsed:.4f}s avg_pps={avg_pps:.2f}")
        return 0
    finally:
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
