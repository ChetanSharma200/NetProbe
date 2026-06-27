"""NetProbe command-line entry point."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from os_fingerprint import fingerprint_os
from output import build_payload, print_banner, print_results, save_results
from scanner import scan_ports
from utils import DEFAULT_COMMON_PORTS, NetProbeError, parse_ports, resolve_target
from banner import prints_banner

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netprobe",
        description="Lightweight TCP reconnaissance for authorized targets.",
        epilog="Use only on systems you own or have explicit permission to assess.",
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address or hostname")
    parser.add_argument(
        "-p",
        "--ports",
        default=None,
        help="Port list or range, for example 22,80,443 or 1-1024",
    )
    parser.add_argument("--banner", action="store_true", help="Enable banner grabbing")
    parser.add_argument("--os", dest="detect_os", action="store_true", help="Enable OS fingerprinting")
    parser.add_argument("-o", "--output", help="Save results to .txt, .json, or .csv")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds")
    parser.add_argument("--threads", type=int, default=100, help="Maximum concurrent scan workers")
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Show closed or filtered ports in terminal output",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    if args.timeout <= 0:
        raise NetProbeError("Timeout must be greater than zero.")
    if args.threads <= 0:
        raise NetProbeError("Thread count must be greater than zero.")

    requested_ports = parse_ports(args.ports)
    target_ip = resolve_target(args.target)

   
    prints_banner()
    if args.ports is None:
        print(f"Scanning {args.target} ({target_ip}) on {len(DEFAULT_COMMON_PORTS)} common ports.")
    else:
        print(f"Scanning {args.target} ({target_ip}) on {len(requested_ports)} TCP ports.")

    started_at = time.perf_counter()
    results = scan_ports(
        target=target_ip,
        ports=requested_ports,
        timeout=args.timeout,
        max_workers=args.threads,
        grab_banners=args.banner,
    )
    elapsed = time.perf_counter() - started_at

    os_info = None
    if args.detect_os:
        open_ports = [result.port for result in results if result.status == "open"]
        os_info = fingerprint_os(target_ip, open_ports=open_ports, timeout=args.timeout)

    print_results(results, elapsed_seconds=elapsed, os_info=os_info, show_closed=args.show_closed)

    if args.output:
        payload = build_payload(
            target=args.target,
            resolved_target=target_ip,
            ports=requested_ports,
            results=results,
            elapsed_seconds=elapsed,
            os_info=os_info,
            banner_enabled=args.banner,
        )
        output_path = save_results(Path(args.output), payload)
        print(f"Saved results to {output_path}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        return 130
    except NetProbeError as exc:
        parser.exit(status=2, message=f"error: {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
