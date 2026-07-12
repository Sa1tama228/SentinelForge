from __future__ import annotations

import urllib.request
import urllib.parse
import hashlib
from functools import lru_cache
from pathlib import Path

from . import config

PROXY_SCHEMES = {"http", "https", "socks4", "socks5"}


def _network_cfg() -> dict:
    return config.load().get("network", {})


def bypass_proxy(url: str) -> bool:
    host = urllib.parse.urlparse(url).hostname or ""
    if not host:
        return False
    raw = _network_cfg().get("no_proxy", "")
    for item in [p.strip().lower() for p in raw.split(",") if p.strip()]:
        if host.lower() == item or host.lower().endswith("." + item.lstrip(".")):
            return True
    return False


def proxy_dict(url: str | None = None) -> dict[str, str]:
    if url and bypass_proxy(url):
        return {}
    cfg = config.load().get("network", {})
    if not cfg.get("use_proxy"):
        return {}
    listed = proxy_from_list(url or "")
    if listed:
        return {"http": listed, "https": listed}
    proxies: dict[str, str] = {}
    if cfg.get("http_proxy"):
        proxies["http"] = cfg["http_proxy"]
    if cfg.get("https_proxy"):
        proxies["https"] = cfg["https_proxy"]
    return proxies


def proxy_from_list(seed: str = "") -> str:
    cfg = config.load().get("network", {})
    proxies = load_proxy_list(cfg.get("proxy_list_path", ""), scheme=normalize_proxy_scheme(cfg.get("proxy_scheme", "http")))
    if not proxies:
        return ""
    digest = hashlib.sha256((seed or "sentinelforge").encode("utf-8", "replace")).digest()
    idx = int.from_bytes(digest[:8], "big") % len(proxies)
    return proxies[idx]


@lru_cache(maxsize=8)
def load_proxy_list(path_value: str, *, scheme: str = "http") -> tuple[str, ...]:
    path_value = (path_value or "").strip()
    if not path_value:
        return ()
    path = Path(path_value).expanduser()
    if not path.is_file():
        return ()
    out = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ()
    for raw in lines:
        proxy = parse_proxy_line(raw, scheme=scheme)
        if proxy:
            out.append(proxy)
    return tuple(dict.fromkeys(out))


def parse_proxy_line(raw: str, *, scheme: str = "http") -> str:
    line = (raw or "").strip()
    if not line or line.startswith("#"):
        return ""
    if "://" in line:
        return line
    parts = line.split(":")
    if len(parts) < 2:
        return ""
    host, port = parts[0].strip(), parts[1].strip()
    if not host or not port.isdigit():
        return ""
    scheme = normalize_proxy_scheme(scheme)
    if len(parts) >= 4:
        user = urllib.parse.quote(parts[2].strip(), safe="")
        password = urllib.parse.quote(":".join(parts[3:]).strip(), safe="")
        return f"{scheme}://{user}:{password}@{host}:{port}"
    return f"{scheme}://{host}:{port}"


def normalize_proxy_scheme(value: str | None) -> str:
    scheme = (value or "http").strip().lower()
    return scheme if scheme in PROXY_SCHEMES else "http"


def opener(url: str | None = None) -> urllib.request.OpenerDirector:
    proxies = proxy_dict(url)
    if proxies:
        return urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
    return urllib.request.build_opener()
