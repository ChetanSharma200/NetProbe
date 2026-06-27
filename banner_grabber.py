"""Service banner collection helpers."""

from __future__ import annotations

import socket
import ssl

from utils import sanitize_banner


HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
HTTPS_PORTS = {443, 8443, 9443}
PASSIVE_BANNER_PORTS = {21, 22, 25, 110, 143, 587, 993, 995}


def grab_banner(target: str, port: int, timeout: float = 1.0) -> str | None:
    """Try to read a short service banner from an open TCP port."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in HTTPS_PORTS:
                return _grab_https_banner(sock, target, port, timeout)
            if port in HTTP_PORTS:
                probe = _http_probe(target)
                sock.sendall(probe)
                return _recv_banner(sock)
            if port in PASSIVE_BANNER_PORTS:
                banner = _recv_banner(sock)
                if banner:
                    return banner

            try:
                sock.sendall(b"\r\n")
            except OSError:
                pass
            return _recv_banner(sock)
    except (OSError, ssl.SSLError):
        return None


def _grab_https_banner(sock: socket.socket, target: str, port: int, timeout: float) -> str | None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with context.wrap_socket(sock, server_hostname=target) as tls_sock:
            tls_sock.settimeout(timeout)
            tls_sock.sendall(_http_probe(target))
            banner = _recv_banner(tls_sock)
            if banner:
                return banner
            cipher = tls_sock.cipher()
            if cipher:
                return f"TLS {cipher[1]} cipher={cipher[0]}"
    except (OSError, ssl.SSLError):
        return None
    return None


def _http_probe(target: str) -> bytes:
    return f"HEAD / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: NetProbe/1.0\r\n\r\n".encode("ascii")


def _recv_banner(sock: socket.socket, byte_limit: int = 1024) -> str | None:
    try:
        data = sock.recv(byte_limit)
    except socket.timeout:
        return None
    except OSError:
        return None

    if not data:
        return None
    return sanitize_banner(data.decode("utf-8", errors="replace"))
