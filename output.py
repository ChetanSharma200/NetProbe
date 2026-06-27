"""Terminal and file output helpers."""

from __future__ import annotations
from banner import prints_banner

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from os_fingerprint import OSFingerprint
from scanner import PortScanResult

try:
    from pyfiglet import Figlet
except ImportError:  # pragma: no cover - optional dependency
    Figlet = None

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:  # pragma: no cover - optional dependency
    Console = None
    Table = None




def print_results(
    results: list[PortScanResult],
    elapsed_seconds: float,
    os_info: OSFingerprint | None = None,
    show_closed: bool = False,
) -> None:
    visible_results = results if show_closed else [item for item in results if item.status == "open"]
    open_count = sum(1 for item in results if item.status == "open")
    filtered_count = sum(1 for item in results if item.status == "filtered")
    closed_count = sum(1 for item in results if item.status == "closed")

    if Console and Table:
        _print_rich_table(visible_results)
    else:
        _print_plain_table(visible_results)

    print(
        f"\nSummary: {open_count} open, {closed_count} closed, "
        f"{filtered_count} filtered in {elapsed_seconds:.2f}s."
    )

    if os_info:
        print(f"\nOS fingerprint: {os_info.probable_os} ({os_info.confidence} confidence)")
        if os_info.ttl is not None:
            print(f"TTL observed: {os_info.ttl}")
        for signal in os_info.signals:
            print(f"- {signal}")


def build_payload(
    target: str,
    resolved_target: str,
    ports: list[int],
    results: list[PortScanResult],
    elapsed_seconds: float,
    os_info: OSFingerprint | None,
    banner_enabled: bool,
) -> dict[str, Any]:
    return {
        "target": target,
        "resolved_target": resolved_target,
        "ports_scanned": ports,
        "banner_enabled": banner_enabled,
        "elapsed_seconds": round(elapsed_seconds, 4),
        "summary": {
            "open": sum(1 for item in results if item.status == "open"),
            "closed": sum(1 for item in results if item.status == "closed"),
            "filtered": sum(1 for item in results if item.status == "filtered"),
        },
        "results": [asdict(item) for item in results],
        "os_fingerprint": os_info.to_dict() if os_info else None,
    }


def save_results(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    suffix = path.suffix.lower()
    if suffix == ".json":
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif suffix == ".csv":
        _save_csv(path, payload)
    else:
        _save_text(path, payload)
    return path.resolve()


def _print_rich_table(results: list[PortScanResult]) -> None:
    console = Console()
    if not results:
        console.print("No visible ports to display.", style="yellow")
        return

    table = Table(title="Scan Results")
    table.add_column("Port", justify="right")
    table.add_column("Status")
    table.add_column("Service")
    table.add_column("Latency")
    table.add_column("Banner")

    for item in results:
        style = "green" if item.status == "open" else "dim"
        table.add_row(
            str(item.port),
            item.status,
            item.service,
            f"{item.latency_ms:.2f} ms" if item.latency_ms is not None else "-",
            item.banner or "",
            style=style,
        )
    console.print(table)


def _print_plain_table(results: list[PortScanResult]) -> None:
    if not results:
        print("No visible ports to display.")
        return

    header = f"{'PORT':>7}  {'STATUS':<9}  {'SERVICE':<16}  {'LATENCY':<10}  BANNER"
    print(header)
    print("-" * len(header))
    for item in results:
        latency = f"{item.latency_ms:.2f} ms" if item.latency_ms is not None else "-"
        print(f"{item.port:>7}  {item.status:<9}  {item.service:<16}  {latency:<10}  {item.banner or ''}")


def _save_csv(path: Path, payload: dict[str, Any]) -> None:
    fieldnames = ["target", "port", "status", "service", "latency_ms", "banner", "error"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in payload["results"]:
            writer.writerow(
                {
                    "target": item["target"],
                    "port": item["port"],
                    "status": item["status"],
                    "service": item["service"],
                    "latency_ms": item["latency_ms"],
                    "banner": item["banner"],
                    "error": item["error"],
                }
            )


def _save_text(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "NetProbe Scan Results",
        f"Target: {payload['target']} ({payload['resolved_target']})",
        f"Elapsed: {payload['elapsed_seconds']}s",
        (
            "Summary: "
            f"{payload['summary']['open']} open, "
            f"{payload['summary']['closed']} closed, "
            f"{payload['summary']['filtered']} filtered"
        ),
        "",
        "Ports:",
    ]
    for item in payload["results"]:
        banner = f" banner={item['banner']}" if item["banner"] else ""
        error = f" error={item['error']}" if item["error"] else ""
        lines.append(
            f"- {item['port']}/tcp {item['status']} service={item['service']}"
            f" latency_ms={item['latency_ms']}{banner}{error}"
        )

    os_info = payload.get("os_fingerprint")
    if os_info:
        lines.extend(
            [
                "",
                f"OS fingerprint: {os_info['probable_os']} ({os_info['confidence']} confidence)",
            ]
        )
        if os_info["ttl"] is not None:
            lines.append(f"TTL observed: {os_info['ttl']}")
        lines.extend(f"- {signal}" for signal in os_info["signals"])

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
