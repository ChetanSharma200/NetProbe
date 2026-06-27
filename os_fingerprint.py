"""Heuristic OS fingerprinting for NetProbe."""

from __future__ import annotations

import platform
import re
import subprocess
from dataclasses import dataclass, asdict


WINDOWS_PORT_HINTS = {135, 139, 445, 3389, 5985, 5986}
UNIX_PORT_HINTS = {22, 111, 2049}
MACOS_PORT_HINTS = {548, 631}
NETWORK_DEVICE_HINTS = {23, 161, 179, 830}


@dataclass(frozen=True)
class OSFingerprint:
    probable_os: str
    confidence: str
    ttl: int | None
    signals: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def fingerprint_os(target: str, open_ports: list[int] | None = None, timeout: float = 1.0) -> OSFingerprint:
    """Infer a probable OS from ping TTL and common service hints."""
    ports = set(open_ports or [])
    signals: list[str] = []
    scores = {"Windows": 0, "Linux/Unix": 0, "macOS": 0, "Network device": 0}

    ttl = get_ttl(target, timeout=timeout)
    if ttl is not None:
        ttl_guess = guess_os_from_ttl(ttl)
        scores[ttl_guess] += 2
        signals.append(f"Observed ping TTL {ttl}, which commonly points to {ttl_guess}.")
    else:
        signals.append("No ping TTL observed; host may block ICMP echo.")

    if ports & WINDOWS_PORT_HINTS:
        scores["Windows"] += 2
        signals.append(f"Windows-oriented ports open: {_format_ports(ports & WINDOWS_PORT_HINTS)}.")
    if ports & UNIX_PORT_HINTS:
        scores["Linux/Unix"] += 1
        signals.append(f"Unix-oriented ports open: {_format_ports(ports & UNIX_PORT_HINTS)}.")
    if ports & MACOS_PORT_HINTS:
        scores["macOS"] += 2
        signals.append(f"macOS-oriented ports open: {_format_ports(ports & MACOS_PORT_HINTS)}.")
    if ports & NETWORK_DEVICE_HINTS:
        scores["Network device"] += 1
        signals.append(f"Network-device-oriented ports open: {_format_ports(ports & NETWORK_DEVICE_HINTS)}.")

    probable_os, score = max(scores.items(), key=lambda item: item[1])
    if score <= 0:
        probable_os = "Unknown"
        confidence = "low"
    elif score <= 2:
        confidence = "low"
    elif score <= 4:
        confidence = "medium"
    else:
        confidence = "high"

    return OSFingerprint(probable_os=probable_os, confidence=confidence, ttl=ttl, signals=signals)


def get_ttl(target: str, timeout: float = 1.0) -> int | None:
    """Ping once and parse TTL from the system ping output."""
    is_windows = platform.system().lower() == "windows"
    if is_windows:
        command = ["ping", "-n", "1", "-w", str(max(1, int(timeout * 1000))), target]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), target]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(2.0, timeout + 1.0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    output = f"{completed.stdout}\n{completed.stderr}"
    match = re.search(r"\bttl[=\s:]+(\d+)\b", output, flags=re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1))


def guess_os_from_ttl(ttl: int) -> str:
    """Map an observed TTL to a likely OS family."""
    if ttl <= 64:
        return "Linux/Unix"
    if ttl <= 128:
        return "Windows"
    return "Network device"


def _format_ports(ports: set[int]) -> str:
    return ", ".join(str(port) for port in sorted(ports))
