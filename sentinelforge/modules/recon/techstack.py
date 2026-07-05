"""HTTP-based technology fingerprinting.

Fetches the site once, then matches header/body signatures against a
small rule set. Passive from the target's POV (a single GET, no probing
of odd paths).
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request

from ...core import config, net
from ...core.text import decode_network_text

# (name, header-substring-lower, body-substring-lower)
_SIGNATURES = [
    ("Apache",            "server: apache",            ""),
    ("nginx",             "server: nginx",             ""),
    ("Microsoft-IIS",     "server: microsoft-iis",     ""),
    ("OpenResty",         "server: openresty",         ""),
    ("LiteSpeed",         "server: litespeed",         ""),
    ("PHP",               "x-powered-by: php",         ""),
    ("ASP.NET",           "x-powered-by: asp.net",     ""),
    ("Express",           "x-powered-by: express",     ""),
    ("WordPress",         "",                           "/wp-content/"),
    ("Joomla",            "",                           "/media/jui/"),
    ("Drupal",            "x-generator: drupal",       "drupal.js"),
    ("React",             "",                           "react-dom"),
    ("Vue.js",            "",                           "data-v-"),
    ("Angular",           "",                           "ng-version"),
    ("Cloudflare",        "server: cloudflare",        ""),
    ("jQuery",            "",                           "jquery"),
    ("Tomcat",            "server: apache-coyote",      ""),
]


def detect(url: str, timeout: float = 10.0, ua: str = "SentinelForge-Recon/0.1") -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    attempts = [url]
    if url.startswith("https://"):
        attempts.append("http://" + url[len("https://"):])

    last_error = ""
    for candidate in attempts:
        result = _fetch_and_detect(candidate, timeout=timeout, ua=ua)
        if "error" not in result:
            return result
        last_error = result["error"]
    return {"error": last_error}


def _fetch_and_detect(url: str, timeout: float, ua: str) -> dict:
    headers_raw = ""
    body = ""
    final_url = url
    status = None
    client = config.load().get("recon", {}).get("http_client", "auto")
    try:
        if client in {"auto", "httpx"}:
            try:
                import httpx

                proxies = net.proxy_dict(url) or None
                with httpx.Client(
                    timeout=timeout,
                    follow_redirects=True,
                    proxy=proxies.get("https") or proxies.get("http") if proxies else None,
                    headers={"User-Agent": ua},
                ) as http:
                    resp = http.get(url)
                status = resp.status_code
                final_url = str(resp.url)
                headers_raw = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                body = decode_network_text(resp.content[:200000])
            except ImportError:
                if client == "httpx":
                    raise
                raise RuntimeError("__urllib_fallback__")
        else:
            raise RuntimeError("__urllib_fallback__")
    except RuntimeError as exc:
        if str(exc) != "__urllib_fallback__":
            return {"error": str(exc)}
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        try:
            with net.opener(url).open(req, timeout=timeout) as resp:
                status = resp.status
                final_url = resp.geturl()
                headers_raw = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                body = decode_network_text(resp.read(200000))
        except urllib.error.HTTPError as he:
            status = he.code
            headers_raw = "\n".join(f"{k}: {v}" for k, v in he.headers.items())
            try:
                body = decode_network_text(he.read(200000))
            except Exception:
                body = ""
        except Exception as exc2:
            return {"error": str(exc2)}
    except urllib.error.HTTPError as he:
        status = he.code
        headers_raw = "\n".join(f"{k}: {v}" for k, v in he.headers.items())
        try:
            body = decode_network_text(he.read(200000))
        except Exception:
            body = ""
    except Exception as exc:
        return {"error": str(exc)}

    low_headers = headers_raw.lower()
    low_body = body.lower()
    techs: list[str] = []
    for name, hsig, bsig in _SIGNATURES:
        if hsig and hsig in low_headers:
            techs.append(name)
        elif bsig and bsig in low_body:
            techs.append(name)

    return {
        "final_url": final_url,
        "status": status,
        "server": _header(headers_raw, "Server"),
        "powered_by": _header(headers_raw, "X-Powered-By"),
        "generator": _header(headers_raw, "X-Generator") or _meta_generator(body),
        "cookies": _cookie_names(headers_raw),
        "title": _title(body),
        "technologies": sorted(set(techs)),
        "security_headers": _security_headers(headers_raw),
    }


def _header(headers_raw: str, name: str) -> str:
    name_l = name.lower()
    for line in headers_raw.split("\n"):
        if ":" in line and line.split(":", 1)[0].strip().lower() == name_l:
            return line.split(":", 1)[1].strip()
    return ""


def _title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body or "", flags=re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:160]


def _meta_generator(body: str) -> str:
    match = re.search(
        r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)",
        body or "",
        flags=re.I,
    )
    return match.group(1).strip()[:160] if match else ""


def _cookie_names(headers_raw: str) -> list[str]:
    names = []
    for line in headers_raw.split("\n"):
        if line.lower().startswith("set-cookie:"):
            value = line.split(":", 1)[1].strip()
            if "=" in value:
                names.append(value.split("=", 1)[0])
    return sorted(set(names))[:20]


def _security_headers(headers_raw: str) -> dict:
    names = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]
    return {name: bool(_header(headers_raw, name)) for name in names}
