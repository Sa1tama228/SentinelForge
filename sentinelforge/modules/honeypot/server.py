from __future__ import annotations

import ssl
import socket
import socketserver
import os
import re
import hashlib
import logging
import struct
import threading
import uuid
from email.parser import Parser
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, parse_qsl, urlencode

from ...core import config, db, events
from ...core.text import decode_network_text, encode_network_text
from . import alert, enrichment

logger = logging.getLogger(__name__)

DEFAULT_HTML = (
    b"<html><head><title>It works!</title></head>"
    b"<body><h1>It works!</h1></body></html>"
)


def _hp_cfg() -> dict:
    return config.load()["honeypot"]


def _line(value: str, fallback: str) -> bytes:
    text = (value or fallback).rstrip("\r\n")
    return encode_network_text(text, newline=True)


def _http_body() -> bytes:
    cfg = _hp_cfg()
    html_file = _read_html_file(cfg.get("http_html_path") or "")
    if html_file is not None:
        return html_file
    body = (cfg.get("http_body") or "").strip()
    if body:
        return body.encode("utf-8", "replace")[:262_144]
    return DEFAULT_HTML


def _read_html_file(path_value: str, *, limit: int = 262_144) -> bytes | None:
    path = (path_value or "").strip()
    if not path:
        return None
    try:
        p = Path(path).expanduser()
        if p.is_file():
            return p.read_bytes()[:limit]
    except OSError:
        return None
    return None


def _login_body(title: str = "Sign in") -> bytes:
    html = (
        "<!doctype html><html><head><title>{0}</title></head><body>"
        "<h1>{0}</h1><form method='post'>"
        "<label>Username <input name='username' autocomplete='username'></label><br>"
        "<label>Password <input name='password' type='password' autocomplete='current-password'></label><br>"
        "<button type='submit'>Sign in</button></form></body></html>"
    ).format(title)
    return html.encode("utf-8", "replace")


def _http_response_for(path: str) -> tuple[str, str, bytes, dict]:
    cfg = _hp_cfg()
    clean_path = path or "/"
    for route in cfg.get("http_routes", []) or []:
        if not isinstance(route, dict):
            continue
        if (route.get("path") or "").strip() == clean_path:
            # Route-specific bodies let operators emulate a service surface
            # without adding handler branches.
            route_body = _read_html_file(str(route.get("html_path") or ""))
            if route_body is None:
                route_body = str(route.get("body") or "").encode("utf-8", "replace")[:262_144]
            return (
                route.get("status") or "200 OK",
                route.get("content_type") or "text/html; charset=utf-8",
                route_body,
                route.get("headers") if isinstance(route.get("headers"), dict) else {},
            )
    if cfg.get("http_login_enabled", True) and clean_path in set(cfg.get("http_login_paths", []) or []):
        login_body = _read_html_file(cfg.get("http_login_html_path") or "")
        if login_body is None:
            login_body = _login_body(cfg.get("http_login_title") or "Sign in")
        return (
            "200 OK",
            "text/html; charset=utf-8",
            login_body,
            {},
        )
    return (
        cfg.get("http_status") or "200 OK",
        cfg.get("http_content_type") or "text/html; charset=utf-8",
        _http_body(),
        {},
    )


def _http_extra_headers(extra: dict | None = None) -> str:
    headers = dict(_hp_cfg().get("http_extra_headers") or {})
    if extra:
        headers.update(extra)
    if not isinstance(headers, dict):
        return ""
    lines = []
    for key, value in headers.items():
        # Header values are config-driven, so strip CR/LF to prevent response
        # splitting while still allowing simple custom headers.
        clean_key = str(key).replace("\r", "").replace("\n", "").strip()
        clean_value = str(value).replace("\r", "").replace("\n", "").strip()
        if clean_key and clean_value:
            lines.append(f"{clean_key}: {clean_value}")
    return "\r\n".join(lines)


def _record(hp_type: str, ip: str, port: int, **fields) -> None:
    # Enrich before persistence so DB rows, UI events, and alerts agree on the
    # same classification and IOC extraction.
    data = enrichment.enrich_event(
        hp_type,
        ip,
        fields.get("method", ""),
        fields.get("path", ""),
        fields.get("headers", ""),
        fields.get("body", ""),
    )
    fields.setdefault("classification", data["classification"])
    fields.setdefault("iocs", data["iocs"])
    fields.setdefault("geo", data["geo"])
    eid = db.add_honeypot_event(hp_type, ip, port, **fields)
    events.emit("honeypot", {"id": eid, "hp_type": hp_type, "src_ip": ip,
                             "src_port": port, **fields})
    alert.play_warning()


def _session_id() -> str:
    return uuid.uuid4().hex[:12]


def _truncate(text: str, limit: int = 2048) -> str:
    return (text or "")[:limit]


def _redact_http_body(body: str) -> str:
    text = body or ""
    if not text:
        return ""
    sensitive = {"password", "passwd", "pwd", "pass", "secret", "token", "api_key", "apikey"}
    try:
        pairs = parse_qsl(text, keep_blank_values=True)
    except ValueError:
        pairs = []
    if pairs:
        redacted = [
            (key, "<redacted>" if key.strip().lower() in sensitive else value)
            for key, value in pairs
        ]
        return _truncate(urlencode(redacted))
    for key in sensitive:
        text = re.sub(
            rf"(?i)([?&\s\"']?{key}\s*[:=]\s*)[^&\s\"']+",
            rf"\1<redacted>",
            text,
        )
    return _truncate(text)


def _stored_body(body: str, *, hp_type: str) -> str:
    mode = str(_hp_cfg().get("credential_storage", "redacted") or "redacted").lower()
    if mode in {"do_not_store", "none", "off"}:
        return ""
    if mode in {"hash_only", "hash"}:
        # Hash-only mode preserves correlation across attempts without storing
        # the submitted secret itself.
        digest = hashlib.sha256((body or "").encode("utf-8", "replace")).hexdigest()
        return f"sha256:{digest}" if body else ""
    if hp_type in {"http", "https"}:
        return _redact_http_body(body)
    return _truncate(body)


def _ssh_disconnect(message: str) -> bytes:
    desc = message.encode("utf-8", "replace")
    lang = b""
    payload = (
        b"\x01"
        + struct.pack(">I", 11)
        + struct.pack(">I", len(desc))
        + desc
        + struct.pack(">I", len(lang))
        + lang
    )
    padding_len = 8 - ((len(payload) + 5) % 8)
    if padding_len < 4:
        padding_len += 8
    packet_len = len(payload) + padding_len + 1
    return struct.pack(">IB", packet_len, padding_len) + payload + os.urandom(padding_len)


class _HTTPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        ip, port = self.client_address[0], self.client_address[1]
        sid = _session_id()
        try:
            self.request.settimeout(5)
            data = self.request.recv(8192)
            if not data:
                return
            text = decode_network_text(data)
            head, _, body = text.partition("\r\n\r\n")
            lines = head.split("\r\n")
            request_line = lines[0] if lines else ""
            method = path = ""
            if " " in request_line:
                method, path, *_ = request_line.split(" ")
            headers_raw = "\n".join(lines[1:])
            parsed_headers = Parser().parsestr(headers_raw)
            split = urlsplit(path)
            query_keys = ",".join(k for k, _ in parse_qsl(split.query, keep_blank_values=True)[:20])
            headers = "\n".join(
                [
                    f"session={sid}",
                    f"request_line={request_line}",
                    f"user_agent={parsed_headers.get('User-Agent', '')}",
                    f"host={parsed_headers.get('Host', '')}",
                    f"content_length={parsed_headers.get('Content-Length', '')}",
                    f"query_keys={query_keys}",
                ]
            )
            proto = "https" if getattr(self.server, "tls_enabled", False) else "http"
            hp_cfg = _hp_cfg()
            _record(proto, ip, port, method=method, path=split.path or path,
                    headers=f"{headers}\npersona={hp_cfg.get('persona', 'custom')}", body=_stored_body(body, hp_type=proto))
            # Look like a real, slightly leaky server to keep the scan going.
            response_path = split.path or path or "/"
            status, content_type, body_bytes, route_headers = _http_response_for(response_path)
            server_header = hp_cfg.get("http_server_header") or "Apache/2.4.52 (Ubuntu)"
            extra_headers = _http_extra_headers(route_headers)
            head_lines = [
                f"HTTP/1.1 {status}",
                f"Server: {server_header}",
                f"Content-Type: {content_type}",
                f"Content-Length: {len(body_bytes)}",
                "Connection: close",
            ]
            if extra_headers:
                head_lines.append(extra_headers)
            head = "\r\n".join(head_lines) + "\r\n\r\n"
            self.request.sendall(encode_network_text(head) + body_bytes)
        except OSError as exc:
            logger.debug("HTTP honeypot handler failed for %s:%s: %s", ip, port, exc)


class _SSHHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        ip, port = self.client_address[0], self.client_address[1]
        sid = _session_id()
        try:
            self.request.settimeout(5)
            self.request.sendall(
                _line(_hp_cfg().get("ssh_banner", ""), "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10")
            )
            data = self.request.recv(4096)
            banner = decode_network_text(data) if data else ""
            persona = _hp_cfg().get("persona", "custom")
            _record("ssh", ip, port, method="BANNER", path="",
                    headers=f"session={sid}\npersona={persona}\nclient_banner={banner.strip()}", body="")
            self.request.sendall(_ssh_disconnect("Protocol mismatch."))
        except OSError as exc:
            logger.debug("SSH honeypot handler failed for %s:%s: %s", ip, port, exc)


class _FTPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        ip, port = self.client_address[0], self.client_address[1]
        sid = _session_id()
        persona = _hp_cfg().get("persona", "custom")
        try:
            self.request.settimeout(5)
            self.request.sendall(_line(_hp_cfg().get("ftp_banner", ""), "220 (vsFTPd 3.0.5)"))
            while True:
                data = self.request.recv(2048)
                if not data:
                    break
                cmd = decode_network_text(data).strip()
                if not cmd:
                    continue
                command = cmd.split(" ", 1)[0].upper()
                logged_cmd = "PASS <redacted>" if command == "PASS" else cmd
                _record("ftp", ip, port, method=command, path=logged_cmd,
                        headers=f"session={sid}\npersona={persona}", body="")
                upper = cmd.upper()
                if upper.startswith("USER"):
                    self.request.sendall(
                        _line(_hp_cfg().get("ftp_user_reply", ""), "331 Please specify the password.")
                    )
                elif upper.startswith("PASS"):
                    self.request.sendall(
                        _line(_hp_cfg().get("ftp_pass_reply", ""), "530 Login incorrect.")
                    )
                elif upper.startswith("QUIT"):
                    self.request.sendall(b"221 Goodbye.\r\n")
                    break
                else:
                    self.request.sendall(b"530 Please login with USER and PASS.\r\n")
        except OSError as exc:
            logger.debug("FTP honeypot handler failed for %s:%s: %s", ip, port, exc)


class _TelnetHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        ip, port = self.client_address[0], self.client_address[1]
        sid = _session_id()
        cfg = _hp_cfg()
        persona = cfg.get("persona", "custom")
        try:
            self.request.settimeout(8)
            self.request.sendall(_line(cfg.get("telnet_banner", ""), "Ubuntu 22.04 LTS"))
            self.request.sendall(encode_network_text(cfg.get("telnet_login_prompt", "login: ")))
            user = decode_network_text(self.request.recv(256)).strip()
            self.request.sendall(encode_network_text(cfg.get("telnet_password_prompt", "Password: ")))
            password = decode_network_text(self.request.recv(256)).strip()
            _record(
                "telnet",
                ip,
                port,
                method="LOGIN",
                path=user,
                headers=f"session={sid}\npersona={persona}\nuser={user}",
                body="password=<redacted>" if password else "",
            )
            self.request.sendall(_line(cfg.get("telnet_fail_reply", ""), "Login incorrect"))
        except OSError as exc:
            logger.debug("Telnet honeypot handler failed for %s:%s: %s", ip, port, exc)


class _SMTPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        ip, port = self.client_address[0], self.client_address[1]
        sid = _session_id()
        cfg = _hp_cfg()
        persona = cfg.get("persona", "custom")
        try:
            self.request.settimeout(8)
            self.request.sendall(_line(cfg.get("smtp_banner", ""), "220 mail.local ESMTP Postfix"))
            while True:
                data = self.request.recv(2048)
                if not data:
                    break
                line = decode_network_text(data).strip()
                if not line:
                    continue
                command = line.split(" ", 1)[0].upper()
                _record(
                    "smtp",
                    ip,
                    port,
                    method=command,
                    path=line[:300],
                    headers=f"session={sid}\npersona={persona}",
                    body="",
                )
                if command in {"EHLO", "HELO"}:
                    self.request.sendall(_line(cfg.get("smtp_ehlo_reply", ""), "250 mail.local"))
                elif command in {"MAIL", "RCPT"}:
                    self.request.sendall(_line(cfg.get("smtp_relay_denied", ""), "554 5.7.1 Relay access denied"))
                elif command == "QUIT":
                    self.request.sendall(b"221 2.0.0 Bye\r\n")
                    break
                else:
                    self.request.sendall(b"502 5.5.2 Command not recognized\r\n")
        except OSError as exc:
            logger.debug("SMTP honeypot handler failed for %s:%s: %s", ip, port, exc)


# Map kind -> (handler class, port-key in config)
_HANDLERS = {
    "http": (_HTTPHandler, "http_port"),
    "ssh": (_SSHHandler, "ssh_port"),
    "ftp": (_FTPHandler, "ftp_port"),
    "telnet": (_TelnetHandler, "telnet_port"),
    "smtp": (_SMTPHandler, "smtp_port"),
}


class _Server(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True
    tls_enabled = False


class HoneypotManager:
    """Start / stop the three honeypots and report their status."""

    def __init__(self) -> None:
        self._servers: dict[str, _Server] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._errors: dict[str, str] = {}
        self._lock = threading.Lock()

    def status(self) -> dict[str, dict]:
        with self._lock:
            return {
                kind: {
                    "running": kind in self._servers,
                    "port": self._port(kind),
                    "host": self._servers[kind].server_address[0]
                    if kind in self._servers
                    else "0.0.0.0",
                }
                for kind in _HANDLERS
            }

    def error(self, kind: str) -> str:
        with self._lock:
            return self._errors.get(kind, "")

    def _port(self, kind: str) -> int:
        return int(config.load()["honeypot"][_HANDLERS[kind][1]])

    def start(self, kind: str) -> bool:
        if kind not in _HANDLERS:
            return False
        with self._lock:
            if kind in self._servers:
                return True
            handler, port_key = _HANDLERS[kind]
            port = int(config.load()["honeypot"][port_key])
            try:
                srv = self._bind_server(port, handler)
                if kind == "http":
                    self._apply_http_tls(srv)
            except OSError as exc:
                self._errors[kind] = f"bind failed on 0.0.0.0:{port}: {exc}"
                return False
            except ssl.SSLError as exc:
                self._errors[kind] = f"TLS configuration failed: {exc}"
                return False
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            self._servers[kind] = srv
            self._threads[kind] = t
            self._errors[kind] = ""
            t.start()
            return True

    def _bind_server(self, port: int, handler) -> _Server:
        try:
            return _Server(("0.0.0.0", port), handler)
        except OSError:
            # Some Windows security products reject wildcard binds. Loopback
            # still provides a usable local honeypot for testing.
            return _Server(("127.0.0.1", port), handler)

    def stop(self, kind: str) -> bool:
        with self._lock:
            srv = self._servers.pop(kind, None)
            self._threads.pop(kind, None)
        if srv is None:
            return False
        srv.shutdown()
        srv.server_close()
        return True

    def _apply_http_tls(self, srv: _Server) -> None:
        cfg = _hp_cfg()
        cert = (cfg.get("http_tls_cert_path") or "").strip()
        key = (cfg.get("http_tls_key_path") or "").strip()
        if not cert and not key:
            return
        if not cert or not key:
            raise ssl.SSLError("both certificate and key paths are required")
        cert_path = Path(cert).expanduser()
        key_path = Path(key).expanduser()
        if not cert_path.is_file() or not key_path.is_file():
            raise ssl.SSLError("certificate or key file does not exist")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        srv.tls_enabled = True

    def stop_all(self) -> None:
        for kind in list(_HANDLERS):
            self.stop(kind)


# Module-level singleton the UI can reuse across view rebuilds.
_manager: Optional[HoneypotManager] = None


def manager() -> HoneypotManager:
    global _manager
    if _manager is None:
        _manager = HoneypotManager()
    return _manager
