"""TCP connect scanner for NetProbe."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from banner_grabber import grab_banner


COMMON_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


@dataclass(frozen=True)
class PortScanResult:
    """Structured result for a single scanned TCP port."""

    target: str
    port: int
    status: str
    service: str
    latency_ms: float | None = None
    banner: str | None = None
    error: str | None = None


def identify_service(port: int) -> str:
    """Return a friendly service name when one is known."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


def scan_port(target: str, port: int, timeout: float = 1.0, grab_banners: bool = False) -> PortScanResult:
    """Scan one TCP port using a regular connect attempt."""
    service = identify_service(port)
    started_at = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target, port))
        latency_ms = round((time.perf_counter() - started_at) * 1000, 2)

        return PortScanResult(
            target=target,
            port=port,
            status="open",
            service=service,
            latency_ms=latency_ms,
            banner=grab_banner(target, port, timeout=timeout) if grab_banners else None,
        )
    except ConnectionRefusedError as exc:
        latency_ms = round((time.perf_counter() - started_at) * 1000, 2)
        return PortScanResult(
            target,
            port,
            "closed",
            service,
            latency_ms,
            error=_format_socket_error(exc),
        )
    except socket.timeout:
        latency_ms = round((time.perf_counter() - started_at) * 1000, 2)
        return PortScanResult(target, port, "filtered", service, latency_ms, error="timeout")
    except OSError as exc:
        latency_ms = round((time.perf_counter() - started_at) * 1000, 2)
        status = _classify_socket_error(exc)
        return PortScanResult(target, port, status, service, latency_ms, error=_format_socket_error(exc))
    finally:
        sock.close()


def scan_ports(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
    max_workers: int = 100,
    grab_banners: bool = False,
) -> list[PortScanResult]:
    """Scan many TCP ports concurrently and return results sorted by port."""
    if not ports:
        return []

    worker_count = min(max_workers, len(ports))
    results: list[PortScanResult] = []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(scan_port, target, port, timeout, grab_banners): port
            for port in ports
        }
        for future in as_completed(future_map):
            results.append(future.result())

    return sorted(results, key=lambda item: item.port)


def _classify_socket_error(exc: OSError) -> str:
    code = exc.errno or getattr(exc, "winerror", None)
    closed_codes = {10061, 10054, 111, 104}
    filtered_codes = {10035, 10036, 10060, 10064, 10065, 110, 113, 115}

    if code in closed_codes:
        return "closed"
    if code in filtered_codes:
        return "filtered"
    return "filtered"


def _format_socket_error(exc: OSError) -> str:
    code = exc.errno or getattr(exc, "winerror", None)
    if code:
        return f"{exc.strerror or exc.__class__.__name__} ({code})"
    return str(exc)
