"""Passive subdomain enumeration from public data sources."""
from __future__ import annotations

import json
from pathlib import Path
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver

from ...core import config, net


def enumerate_subdomains(domain: str, timeout: float = 20.0) -> list[str]:
    return enumerate_with_sources(domain, timeout=timeout)["names"]


def enumerate_with_sources(domain: str, timeout: float = 20.0) -> dict:
    recon_cfg = config.load().get("recon", {})
    cfg_sources = recon_cfg.get("subdomain_sources", [])
    sources = set(cfg_sources or ["crtsh"])
    names: set[str] = set()
    meta: dict[str, dict] = {}
    collectors = []
    if "crtsh" in sources:
        collectors.append(("crtsh", lambda: _from_crtsh(domain, timeout)))
    if "hackertarget" in sources:
        collectors.append(("hackertarget", lambda: _from_hackertarget(domain, timeout)))
    if "dnsdumpster" in sources:
        collectors.append(("dnsdumpster", lambda: _from_dnsdumpster(domain, timeout)))

    rate_delay = float(recon_cfg.get("source_rate_delay_sec", 0.0) or 0.0)
    if rate_delay > 0:
        for idx, (name, fn) in enumerate(collectors):
            if idx:
                time.sleep(rate_delay)
            found, error = _capture_source(fn)
            names.update(found)
            meta[name] = {"count": len(found), "error": error}
    elif collectors:
        with ThreadPoolExecutor(max_workers=min(3, len(collectors))) as pool:
            futures = {pool.submit(_capture_source, fn): name for name, fn in collectors}
            for future in as_completed(futures):
                name = futures[future]
                found, error = future.result()
                names.update(found)
                meta[name] = {"count": len(found), "error": error}

    if recon_cfg.get("wordlist_enabled"):
        found, error = _capture_source(lambda: _from_wordlist(domain, timeout))
        names.update(found)
        meta["wordlist"] = {"count": len(found), "error": error}

    return {"names": sorted(names), "sources": {k: v for k, v in meta.items() if v["count"] or v["error"]}}


def _capture_source(fn) -> tuple[set[str], str]:
    try:
        return fn(), ""
    except Exception as exc:
        return set(), str(exc)


def _from_crtsh(domain: str, timeout: float) -> set[str]:
    url = f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "SentinelForge-Recon/0.1"})
    with net.opener(url).open(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))

    names: set[str] = set()
    for entry in data:
        for field in ("name_value", "common_name"):
            val = entry.get(field, "")
            if not val:
                continue
            for line in val.split("\n"):
                host = line.strip().lower().rstrip(".")
                if _belongs_to_domain(host, domain) and "*" not in host:
                    names.add(host)
    return names


def _from_hackertarget(domain: str, timeout: float) -> set[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
    req = urllib.request.Request(url, headers={"User-Agent": "SentinelForge-Recon/0.1"})
    with net.opener(url).open(req, timeout=timeout) as resp:
        text = resp.read(500000).decode("utf-8", "replace")

    names: set[str] = set()
    for line in text.splitlines():
        host = line.split(",", 1)[0].strip().lower().rstrip(".")
        if _belongs_to_domain(host, domain) and "*" not in host:
            names.add(host)
    return names


def _from_dnsdumpster(domain: str, timeout: float) -> set[str]:
    # DNSDumpster has no stable unauthenticated JSON API. This only consumes a
    # static map artifact if it exists; it does not submit forms or brute force.
    url = f"https://dnsdumpster.com/static/map/{urllib.parse.quote(domain)}.json"
    req = urllib.request.Request(url, headers={"User-Agent": "SentinelForge-Recon/0.1"})
    with net.opener(url).open(req, timeout=timeout) as resp:
        text = resp.read(500000).decode("utf-8", "replace")

    names: set[str] = set()
    for token in text.replace('"', "\n").replace(",", "\n").splitlines():
        host = token.strip().lower().rstrip(".")
        if _belongs_to_domain(host, domain) and "*" not in host:
            names.add(host)
    return names


def _belongs_to_domain(host: str, domain: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    domain = (domain or "").strip().lower().rstrip(".")
    return bool(host and domain and (host == domain or host.endswith("." + domain)))


def _from_wordlist(domain: str, timeout: float) -> set[str]:
    cfg = config.load()
    recon = cfg.get("recon", {})
    path = (recon.get("wordlist_path") or "").strip()
    if not path:
        return set()
    wordlist = Path(path).expanduser()
    if not wordlist.is_file():
        return set()
    limit = int(recon.get("wordlist_limit") or 2000)
    resolver = dns.resolver.Resolver()
    resolvers = recon.get("resolvers") or []
    if resolvers:
        resolver.nameservers = resolvers
    resolver.lifetime = min(timeout, 3.0)
    resolver.timeout = min(timeout, 2.0)

    names: set[str] = set()
    try:
        words = wordlist.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return names
    for raw in words[:limit]:
        word = raw.strip().lower()
        if not word or word.startswith("#") or "/" in word or " " in word:
            continue
        host = f"{word}.{domain}".rstrip(".")
        try:
            resolver.resolve(host, "A")
        except Exception:
            continue
        names.add(host)
    return names
