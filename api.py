"""FastAPI Backend Server for NetProbe (run with uvicorn api:app --reload)."""

from __future__ import annotations

import time
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from os_fingerprint import fingerprint_os
from output import build_payload
from scanner import scan_ports
from utils import NetProbeError, parse_ports, resolve_target

app = FastAPI(
    title="NetProbe REST API",
    description="High-performance TCP port scanner and OS fingerprinting API.",
    version="1.0.0",
)


class ScanRequest(BaseModel):
    target: str = Field(..., example="127.0.0.1", description="Target IP or hostname")
    ports: Optional[str] = Field(None, example="22,80,443", description="Port range or comma-separated list")
    timeout: float = Field(1.0, ge=0.1, le=10.0, description="Socket connection timeout in seconds")
    threads: int = Field(100, ge=1, le=500, description="Max concurrent scanning threads")
    grab_banners: bool = Field(True, description="Enable service banner grabbing")
    detect_os: bool = Field(True, description="Enable OS fingerprinting")


@app.get("/")
def root():
    return {
        "message": "Welcome to NetProbe API",
        "docs": "/docs",
        "version": "1.0.0",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
def run_scan(req: ScanRequest):
    try:
        target_ip = resolve_target(req.target)
        requested_ports = parse_ports(req.ports)
    except NetProbeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    started_at = time.perf_counter()
    results = scan_ports(
        target=target_ip,
        ports=requested_ports,
        timeout=req.timeout,
        max_workers=req.threads,
        grab_banners=req.grab_banners,
    )
    elapsed = time.perf_counter() - started_at

    os_info = None
    if req.detect_os:
        open_ports = [result.port for result in results if result.status == "open"]
        os_info = fingerprint_os(target_ip, open_ports=open_ports, timeout=req.timeout)

    return build_payload(
        target=req.target,
        resolved_target=target_ip,
        ports=requested_ports,
        results=results,
        elapsed_seconds=elapsed,
        os_info=os_info,
        banner_enabled=req.grab_banners,
    )
