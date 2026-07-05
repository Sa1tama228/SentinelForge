"""Service + version fingerprinting from port number and banner text."""
from __future__ import annotations

import re

# Well-known port -> default service name.
_PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
}


def identify(port: int, banner: str) -> tuple[str, str]:
    """Return (service, version) guessed from port + banner."""
    service = _PORT_SERVICE.get(port, "unknown")
    version = ""

    b = banner or ""
    low = b.lower()

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
    # common "product/version" formats so the CVE matcher has something useful.
    m = re.search(r"server:\s*([^\r\n]+)", low)
    if m:
        server = m.group(1).strip()
        service = "https" if port in (443, 8443) else "http"
        version = _normalize_product_version(server)
        return service, version
    m = re.search(r"(apache|nginx|microsoft-iis|openresty|litespeed|caddy)[/\s-]*(\d[\w.\-]+)", low)
    if m:
        service = "https" if port in (443, 8443) else "http"
        return service, f"{m.group(1)} {m.group(2)}"

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
