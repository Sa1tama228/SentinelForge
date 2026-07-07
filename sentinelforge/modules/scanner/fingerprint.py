from __future__ import annotations
from .service_ports import _PORT_SERVICE, looks_like_https_port
import re


def identify(port: int, banner: str) -> tuple[str, str]:
    """Return (service, version) guessed from port + banner."""
    service = _PORT_SERVICE.get(port, "unknown") # This is only a fallback when banner evidence are weak
    version = ""

    b = banner or ""
    low = b.lower()
    is_tls_port = looks_like_https_port(port)
    is_tls_http = "tls cert " in low or " tls_version=" in low or " alpn=" in low
    is_http = low.startswith("http/") or "\nhttp/" in low or "server:" in low

    # SSH:  SSH-2.0-OpenSSH_8.9p1 Ubuntu-...
    m = re.search(r"SSH-[\d.]+-(\S+?)_([\w.+-]+)", b)
    if m:
        service = "ssh"
        version = f"{m.group(1)} {m.group(2)}"
        return service, version
    m = re.search(r"(openssh)\s+([\w.+-]+)", low)
    if m:
        return "ssh", f"{m.group(1)} {m.group(2)}"

    # FTP:  220 (vsFTPd 3.0.5)   /   220 ProFTPD 1.3.5a Server
    m = re.search(r"(vsftpd|proftpd|filezilla|pure-ftpd)[^\d]*(\d[\w.]+)", low)
    if m:
        service = "ftp"
        version = f"{m.group(1)} {m.group(2)}"
        return service, version

    # HTTP Server header. Keep the full server token for display, but normalize
    # common "product/version" formats so the CVE matcher has something useful
    m = re.search(r"server:\s*([^\r\n]+)", low)
    if m:
        server = m.group(1).strip()
        service = "https" if is_tls_http or is_tls_port else "http"
        version = _normalize_product_version(server)
        return service, version
    m = re.search(r"(apache|nginx|microsoft-iis|openresty|litespeed|caddy)[/\s-]*(\d[\w.\-]+)", low)
    if m:
        service = "https" if is_tls_http or is_tls_port else "http"
        return service, f"{m.group(1)} {m.group(2)}"
    if is_tls_http:
        return "https", ""
    if is_http:
        return "http", ""

    # MySQL / Redis / SMTP / etc. banner keywords
    if "udp response" in low:
        token = low.split(" ", 1)[0]
        if token in {"dns", "ntp", "snmp", "ike"}:
            service = token
            version = ""
    elif "mysql" in low:
        service, version = "mysql", _ver_after(low, "mysql")
    elif "redis" in low:
        service, version = "redis", _ver_after(low, "redis")
    elif "smtp" in low or "postfix" in low:
        service, version = "smtp", _ver_after(low, "postfix") or "ESMTP"
    elif "microsoft" in low and "rdp" in (low + str(port)):
        service = "rdp"

    return service, version


def _normalize_product_version(server: str) -> str:
    for token in server.split():
        m = re.match(r"(apache|nginx|microsoft-iis|openresty|litespeed|caddy)/?([\w.\-]+)?", token, flags=re.I)
        if m and m.group(2):
            return f"{m.group(1).lower()} {m.group(2)}"
    return server


def _ver_after(text: str, key: str) -> str:
    m = re.search(re.escape(key) + r"[^\d]*(\d[\w.\-]+)", text)
    return m.group(1) if m else ""
