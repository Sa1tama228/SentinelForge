from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

_UDP_PAYLOADS = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01",
    123: b"\x1b" + b"\x00" * 47,
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x69\x6e\x67\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    500: b"\x00" * 8 + b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x1c",
}

_UDP_SERVICES = {
    53: "dns",
    123: "ntp",
    161: "snmp",
    500: "ike",
}


def scan_udp(host: str, ports: Iterable[int], *, timeout: float = 1.5, max_threads: int = 50) -> list[tuple[int, str]]:
    port_list = [port for port in ports if port in _UDP_PAYLOADS]
    if not port_list:
        return []
    rows: list[tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_threads, len(port_list)))) as pool:
        futures = [pool.submit(_probe_udp, host, port, timeout) for port in port_list]
        for future in as_completed(futures):
            row = future.result()
            if row:
                rows.append(row)
    return sorted(rows, key=lambda item: item[0])


def _probe_udp(host: str, port: int, timeout: float) -> tuple[int, str] | None:
    payload = _UDP_PAYLOADS.get(port)
    if payload is None:
        return None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(payload, (host, port))
            data, _addr = sock.recvfrom(1024)
        except OSError:
            return None
    service = _UDP_SERVICES.get(port, "udp")
    sample = data[:120].hex()
    return port, f"{service} UDP response bytes={len(data)} hex={sample}"
