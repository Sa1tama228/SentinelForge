from __future__ import annotations

import re
import shlex
import shutil
import socket
import ssl
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import perf_counter
from typing import Iterable

from ...core.text import decode_network_text
from .service_ports import HTTP_PORTS, looks_like_https_port

_MAX_PORTS_PER_SCAN = 65535
_BANNER_LIMIT = 2048


def _probe(host: str, port: int, timeout: float, server_name: str | None = None) -> tuple[int, str] | None:
    started = perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    latency_ms = int((perf_counter() - started) * 1000)
    banner = ""
    try:
        sock.settimeout(timeout)
        # using protocol-specific low-impact handshakes only where they produce
        # better evidence than a blind recv
        if looks_like_https_port(port):
            try:
                banner = _https_probe(sock, host=server_name or host, timeout=timeout)
            except OSError:
                banner = ""
        elif port in HTTP_PORTS:
            banner = _http_probe(sock, host=server_name or host)
        elif port in {25, 587}:
            banner = _line_probe(sock, b"EHLO sentinelforge.local\r\n", timeout)
        elif port == 21:
            banner = _line_probe(sock, b"SYST\r\n", timeout)
        elif port == 6379:
            banner = _line_probe(sock, b"INFO\r\n", timeout)
        else:
            try:
                banner = decode_network_text(sock.recv(512))
            except socket.timeout:
                banner = ""
    finally:
        sock.close()
    return port, _normalize_banner(banner, latency_ms)


def _http_probe(sock: socket.socket, *, host: str) -> str:
    req = (
        f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: SentinelForge/0.2\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    ).encode("latin-1", "replace")
    sock.sendall(req)
    chunks = []
    while sum(len(c) for c in chunks) < _BANNER_LIMIT:
        try:
            chunk = sock.recv(1024)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return decode_network_text(b"".join(chunks)[:_BANNER_LIMIT])


def _line_probe(sock: socket.socket, payload: bytes, timeout: float) -> str:
    initial = b""
    try:
        initial = sock.recv(512)
    except socket.timeout:
        pass
    try:
        sock.sendall(payload)
        sock.settimeout(timeout)
        response = sock.recv(1024)
    except OSError:
        response = b""
    return decode_network_text(initial + response)


def _https_probe(sock: socket.socket, *, host: str, timeout: float) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1", "h2"])
    except NotImplementedError:
        pass
    with ctx.wrap_socket(sock, server_hostname=host if _looks_like_dns_name(host) else None) as tls:
        tls.settimeout(timeout)
        cert = tls.getpeercert(binary_form=False) or {}
        tls_version = tls.version() or "-"
        cipher = tls.cipher()[0] if tls.cipher() else "-"
        alpn = tls.selected_alpn_protocol() or "-"
        response = _http_probe(tls, host=host)
    issuer = ", ".join("=".join(part) for group in cert.get("issuer", []) for part in group)
    subject = ", ".join("=".join(part) for group in cert.get("subject", []) for part in group)
    sans = ",".join(value for kind, value in cert.get("subjectAltName", []) if kind.lower() == "dns")
    cert_line = (
        f"TLS cert subject={subject or '-'} issuer={issuer or '-'} "
        f"san={sans or '-'} tls_version={tls_version} cipher={cipher} alpn={alpn}"
    )
    return f"{response}\n{cert_line}"


def _looks_like_dns_name(value: str) -> bool:
    return bool(re.search(r"[a-zA-Z]", value)) and not value.startswith("[")


def _normalize_banner(banner: str, latency_ms: int) -> str:
    text = _clean_banner_text(banner or "")
    title = _html_title(text)
    meta = [f"latency_ms={latency_ms}"]
    if title:
        meta.append(f"title={title[:120]}")
    if text:
        return f"{text[:_BANNER_LIMIT]}\n[scan] " + " ".join(meta)
    return "[scan] " + " ".join(meta)


def _clean_banner_text(banner: str) -> str:
    # Normalize a CRLF pair once. Replacing each carriage return separately
    # creates a false blank line after every HTTP header.
    text = (banner or "").replace("\r\n", "\n").replace("\r", "\n")
    if "\x00" in text:
        return _clean_binary_banner(text)
    return _strip_control_noise(text).strip()


def _clean_binary_banner(text: str) -> str:
    chunks = []
    for raw in text.split("\x00"):
        chunk = _strip_control_noise(raw).strip()
        if _useful_binary_chunk(chunk):
            chunks.append(chunk)
    if chunks:
        return " ".join(chunks)[:_BANNER_LIMIT].strip()
    return _strip_control_noise(text.replace("\x00", " ")).strip()


def _strip_control_noise(text: str) -> str:
    cleaned = []
    for ch in text:
        if ch in "\n\t":
            cleaned.append(ch)
        elif ch.isprintable():
            cleaned.append(ch)
        else:
            cleaned.append(" ")
    return re.sub(r"[ \t]+", " ", "".join(cleaned))


def _useful_binary_chunk(chunk: str) -> bool:
    if len(chunk) < 3:
        return False
    ascii_chars = sum(1 for ch in chunk if ord(ch) < 128)
    ascii_ratio = ascii_chars / max(len(chunk), 1)
    if ascii_ratio < 0.82:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+\- ]{2,}", chunk))


def _html_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()


def scan_ports(host: str, ports: Iterable[int], *,
               timeout: float = 1.5, max_threads: int = 200,
               engine: str = "socket", server_name: str | None = None,
               nmap_extra_flags: str = "", cancel_event=None) -> list[tuple[int, str]]:
    port_list = list(ports)
    if not port_list:
        return []
    if engine in {"auto", "nmap"} and shutil.which("nmap"):
        # Prefer nmap when it is available, but fall back to the socket scanner
        # in auto mode if nmap returns no usable service rows.
        nmap_rows = _scan_with_nmap(host, port_list, timeout=timeout, extra_flags=nmap_extra_flags, cancel_event=cancel_event)
        if nmap_rows or engine == "nmap":
            return nmap_rows
    worker_count = max(1, min(int(max_threads), len(port_list)))
    open_ports: list[tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = [pool.submit(_probe, host, p, timeout, server_name) for p in port_list]
        for fut in as_completed(futures):
            if cancel_event is not None and cancel_event.is_set():
                break
            try:
                res = fut.result()
            except OSError:
                continue
            if res is not None:
                open_ports.append(res)
    open_ports.sort(key=lambda x: x[0])
    return open_ports


def _scan_with_nmap(host: str, ports: list[int], *, timeout: float, extra_flags: str = "", cancel_event=None) -> list[tuple[int, str]]:
    port_spec = ",".join(str(p) for p in ports)
    timeout_s = max(10, int(timeout * max(len(ports), 1)) + 10)
    extra_args = _nmap_extra_args(extra_flags)
    try:
        proc = subprocess.Popen(
            [
                "nmap",
                *extra_args,
                "-sV",
                "--version-light",
                "-oX",
                "-",
                "-p",
                port_spec,
                host,
            ],
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + timeout_s
        while proc.poll() is None:
            # Poll so cancellation from the UI can terminate the child process
            # promptly instead of waiting for communicate() to return.
            if cancel_event is not None and cancel_event.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                return []
            if time.monotonic() >= deadline:
                proc.kill()
                return []
            time.sleep(0.1)
        stdout, _stderr = proc.communicate()
    except OSError:
        return []
    if proc.returncode not in (0, 1) or not stdout.strip():
        return []
    rows: list[tuple[int, str]] = []
    try:
        root = ET.fromstring(stdout)
    except ET.ParseError:
        return []
    for port_el in root.findall(".//port"):
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        port_id = int(port_el.get("portid", "0"))
        service = port_el.find("service")
        if service is None:
            rows.append((port_id, ""))
            continue
        parts = [
            service.get("product", ""),
            service.get("version", ""),
            service.get("extrainfo", ""),
        ]
        name = service.get("name", "")
        banner = " ".join(p for p in parts if p).strip() or name
        rows.append((port_id, banner))
    rows.sort(key=lambda x: x[0])
    return rows


def _nmap_extra_args(raw: str) -> list[str]:
    if not raw:
        return []
    try:
        parts = shlex.split(raw, posix=False)
    except ValueError:
        return []
    blocked_with_values = {"-oX", "-oA", "-oG", "-oN", "-oS", "-p", "-iL", "-iR"} # will add/reduce in the future
    blocked_prefixes = ("--script-args-file", "--exclude-file")
    out: list[str] = []
    idx = 0
    while idx < len(parts):
        part = parts[idx]
        flag = part.split("=", 1)[0]
        # Keep target, port, and output ownership in this module even when
        # advanced nmap timing flags are supplied from config
        if flag in blocked_with_values or any(flag.startswith(prefix) for prefix in blocked_prefixes):
            if "=" not in part:
                idx += 2
            else:
                idx += 1
            continue
        if part.startswith("-"):
            out.append(part)
            if "=" not in part and idx + 1 < len(parts) and not parts[idx + 1].startswith("-"):
                out.append(parts[idx + 1])
                idx += 2
                continue
        idx += 1
    return out


def parse_ports(spec: str) -> list[int]:
    # Accept comma-separated ports and ranges, then validate before any scan worker is started
    out: set[int] = set()
    for token in spec.replace(" ", "").split(","):
        if not token:
            continue
        if "-" in token:
            a, b = token.split("-", 1)
            if not a.isdigit() or not b.isdigit():
                raise ValueError(f"Invalid port range: {token}")
            start, end = int(a), int(b)
            if start > end:
                raise ValueError(f"Invalid port range: {token}")
            out.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid port: {token}")
            out.add(int(token))
    if not out:
        raise ValueError("No ports specified")
    invalid = [p for p in out if p < 1 or p > 65535]
    if invalid:
        raise ValueError(f"Port out of range: {invalid[0]}")
    if len(out) > _MAX_PORTS_PER_SCAN:
        raise ValueError(f"Too many ports: {len(out)} (max {_MAX_PORTS_PER_SCAN})")
    return sorted(out)
