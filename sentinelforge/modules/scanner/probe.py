from __future__ import annotations

import socket


def scapy_ping(host: str, timeout: float = 1.0) -> dict:
    """Best-effort ICMP reachability using Scapy.

    On Windows this may require Npcap/admin privileges. Failure is reported
    as metadata and must not block TCP scanning.
    """
    try:
        from scapy.all import ICMP, IP, sr1
    except Exception as exc:
        return {"engine": "scapy", "ok": False, "available": False, "error": str(exc)}

    try:
        packet = IP(dst=host) / ICMP()
        reply = sr1(packet, timeout=timeout, verbose=False)
    except Exception as exc:
        return {"engine": "scapy", "ok": False, "available": True, "error": str(exc)}

    return {
        "engine": "scapy",
        "ok": reply is not None,
        "available": True,
        "src": getattr(reply, "src", "") if reply is not None else "",
    }


def tcp_probe(host: str, ports: list[int], timeout: float = 0.5) -> dict:
    """Fallback reachability signal using a short TCP connect attempt."""
    for port in ports[: min(len(ports), 16)]:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return {"engine": "tcp", "ok": True, "port": port}
        except OSError:
            continue
    return {"engine": "tcp", "ok": False}
