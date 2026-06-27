"""Shared NetProbe utility functions."""

from __future__ import annotations

import ipaddress
import socket


DEFAULT_COMMON_PORTS = [
    20,
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    1723,
    2049,
    3306,
    3389,
    5432,
    5900,
    6379,
    8000,
    8080,
    8443,
    9200,
    27017,
]


class NetProbeError(Exception):
    """Raised when user input cannot be used safely."""


def parse_ports(port_spec: str | None) -> list[int]:
    """Parse a comma-separated port specification into sorted TCP port numbers."""
    if not port_spec:
        return DEFAULT_COMMON_PORTS.copy()

    ports: set[int] = set()
    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start = _parse_single_port(start_text.strip())
            end = _parse_single_port(end_text.strip())
            if start > end:
                raise NetProbeError(f"Invalid port range {chunk!r}: start is greater than end.")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_single_port(chunk))

    if not ports:
        raise NetProbeError("No valid ports were provided.")
    return sorted(ports)


def resolve_target(target: str) -> str:
    """Resolve an IP address or hostname into an IPv4 address."""
    if not target or not target.strip():
        raise NetProbeError("Target cannot be empty.")

    target = target.strip()
    try:
        parsed_ip = ipaddress.ip_address(target)
        if parsed_ip.version != 4:
            raise NetProbeError("IPv6 targets are not supported by this IPv4 TCP scanner yet.")
        return target
    except ValueError:
        pass

    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise NetProbeError(f"Could not resolve target {target!r}.") from exc


def sanitize_banner(text: str, limit: int = 180) -> str:
    """Clean banner text for terminal and file output."""
    cleaned = " ".join(text.replace("\x00", "").split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."


def _parse_single_port(value: str) -> int:
    try:
        port = int(value, 10)
    except ValueError as exc:
        raise NetProbeError(f"Invalid port {value!r}.") from exc

    if port < 1 or port > 65535:
        raise NetProbeError(f"Port {port} is outside the valid range 1-65535.")
    return port
