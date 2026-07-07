from __future__ import annotations

import re


def extract_metadata(port: int, service: str, banner: str) -> dict:
    service_l = (service or "").lower()
    text = banner or ""
    if service_l in {"http", "https", "http-proxy", "https-alt"} or _looks_like_http_banner(text):
        return _http_metadata(text)
    if service_l == "ssh" or port == 22:
        return _ssh_metadata(text)
    if service_l == "ftp" or port == 21:
        return _ftp_metadata(text)
    if service_l == "smtp" or port in {25, 587}:
        return _smtp_metadata(text)
    if service_l == "mysql" or port == 3306:
        return _mysql_metadata(text)
    if service_l == "redis" or port == 6379:
        return _redis_metadata(text)
    if service_l == "postgresql" or port == 5432:
        return {"protocol": "postgresql", "signals": ["open-postgresql-service"]}
    return {"protocol": service_l or "unknown", "signals": []}


def _looks_like_http_banner(text: str) -> bool:
    low = (text or "").lower()
    return low.startswith("http/") or "\nhttp/" in low or "server:" in low or "tls cert " in low


def _http_metadata(text: str) -> dict:
    headers, _, body = text.partition("\n\n")
    if "\r\n\r\n" in text:
        headers, _, body = text.partition("\r\n\r\n")
    meta = {
        "protocol": "http",
        "status": "",
        "server": _header(headers, "Server"),
        "powered_by": _header(headers, "X-Powered-By"),
        "generator": _header(headers, "X-Generator") or _meta_generator(body),
        "cookies": _cookie_names(headers),
        "security_headers": {
            name: bool(_header(headers, name))
            for name in (
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
            )
        },
        "signals": [],
    }
    first = headers.splitlines()[0] if headers.splitlines() else ""
    match = re.match(r"HTTP/\S+\s+(\d+)", first, flags=re.I)
    if match:
        meta["status"] = match.group(1)
    missing = [name for name, present in meta["security_headers"].items() if not present]
    if missing:
        meta["signals"].append("missing-security-headers")
    if meta["cookies"]:
        meta["signals"].append("sets-cookies")
    if any(token in body.lower() for token in ("wp-content", "phpmyadmin", "login", "admin")):
        meta["signals"].append("admin-or-cms-surface")
    return meta


def _ssh_metadata(text: str) -> dict:
    match = re.search(r"SSH-(?P<proto>[\d.]+)-(?P<software>[^\s]+)", text)
    software = match.group("software") if match else ""
    return {
        "protocol": "ssh",
        "ssh_protocol": match.group("proto") if match else "",
        "software": software,
        "signals": ["ssh-service"] + (["openssh"] if "openssh" in software.lower() else []),
    }


def _ftp_metadata(text: str) -> dict:
    return {
        "protocol": "ftp",
        "banner_code": text.strip().split(" ", 1)[0] if text.strip() else "",
        "anonymous_hint": "anonymous" in text.lower(),
        "signals": ["cleartext-auth-service"],
    }


def _smtp_metadata(text: str) -> dict:
    low = text.lower()
    capabilities = sorted(set(re.findall(r"\b(STARTTLS|AUTH|PIPELINING|SIZE|8BITMIME)\b", text, flags=re.I)))
    signals = ["mail-service"]
    if "auth" in low:
        signals.append("auth-advertised")
    if "starttls" not in low:
        signals.append("starttls-not-observed")
    return {"protocol": "smtp", "capabilities": capabilities, "signals": signals}


def _mysql_metadata(text: str) -> dict:
    low = text.lower()
    auth_plugin = ""
    for plugin in ("mysql_native_password", "caching_sha2_password", "sha256_password"):
        if plugin in low:
            auth_plugin = plugin
            break
    return {
        "protocol": "mysql",
        "auth_plugin": auth_plugin,
        "signals": ["database-service"] + (["legacy-auth-plugin"] if auth_plugin == "mysql_native_password" else []),
    }


def _redis_metadata(text: str) -> dict:
    low = text.lower()
    return {
        "protocol": "redis",
        "mode": "standalone" if "redis_mode:standalone" in low else "",
        "version": _line_value(text, "redis_version"),
        "signals": ["database-service", "often-unauthenticated-if-exposed"],
    }


def _header(headers: str, name: str) -> str:
    name_l = name.lower()
    for line in headers.splitlines():
        if ":" in line and line.split(":", 1)[0].strip().lower() == name_l:
            return line.split(":", 1)[1].strip()
    return ""


def _cookie_names(headers: str) -> list[str]:
    names = []
    for line in headers.splitlines():
        if line.lower().startswith("set-cookie:"):
            value = line.split(":", 1)[1].strip()
            if "=" in value:
                names.append(value.split("=", 1)[0])
    return sorted(set(names))[:20]


def _meta_generator(body: str) -> str:
    match = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", body or "", flags=re.I)
    return match.group(1).strip()[:160] if match else ""


def _line_value(text: str, key: str) -> str:
    match = re.search(rf"^{re.escape(key)}:(.+)$", text or "", flags=re.I | re.M)
    return match.group(1).strip() if match else ""
