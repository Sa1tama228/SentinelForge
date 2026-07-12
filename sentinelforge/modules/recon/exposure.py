from __future__ import annotations

import re
import urllib.error
import urllib.request

from ...core import net
from ...core.text import decode_network_text

CHECKS = {
    "/robots.txt": ("Info", "Robots file exposed"),
    "/sitemap.xml": ("Info", "Sitemap exposed"),
    "/.git/HEAD": ("High", "Exposed Git metadata"),
    "/.env": ("High", "Potential exposed environment file"),
    "/server-status": ("Medium", "Server status endpoint reachable"),
}


def check(domain: str, *, ua: str, timeout: float = 5.0) -> dict:
    base = domain if domain.startswith(("http://", "https://")) else "https://" + domain
    results = []
    for path, (severity, title) in CHECKS.items():
        url = base.rstrip("/") + path
        status, sample, final_url = _head_or_get(
            url,
            ua=ua,
            timeout=timeout,
            fetch_body=path not in {"/robots.txt", "/sitemap.xml"},
        )
        if status is None:
            continue
        if _interesting(path, status, sample):
            results.append(
                {
                    "path": path,
                    "url": final_url,
                    "status": status,
                    "severity": severity,
                    "title": title,
                    "sample": sample[:180],
                    "confidence": "medium" if status in {200, 206} else "low",
                }
            )
    return {"checks": results, "count": len(results)}


def _head_or_get(url: str, *, ua: str, timeout: float,
                 fetch_body: bool = True) -> tuple[int | None, str, str]:
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": ua})
    head_status = None
    final_url = url
    try:
        with net.opener(url).open(req, timeout=timeout) as resp:
            head_status = resp.status
            final_url = resp.geturl()
    except urllib.error.HTTPError as exc:
        head_status = exc.code
        final_url = exc.geturl()
        if exc.code not in {200, 206, 401, 403, 405}:
            return exc.code, "", url
    except Exception:
        return None, "", url
    if head_status not in {200, 206, 401, 403, 405}:
        return head_status, "", final_url
    if not fetch_body and head_status != 405:
        return head_status, "", final_url

    # HEAD is useful for avoiding unnecessary bodies, but sensitive-file
    # checks need bounded content evidence before they can become findings.
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": ua})
    try:
        with net.opener(url).open(req, timeout=timeout) as resp:
            body = decode_network_text(resp.read(512))
            return resp.status, body, resp.geturl()
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = decode_network_text(exc.read(512))
        except Exception:
            pass
        return exc.code, body, url
    except Exception:
        return None, "", url


def _interesting(path: str, status: int, sample: str) -> bool:
    if path in {"/robots.txt", "/sitemap.xml"}:
        return status == 200
    if path == "/.git/HEAD":
        text = sample.strip()
        return status in {200, 206} and bool(
            re.search(r"^ref:\s+refs/", text, flags=re.I)
            or re.fullmatch(r"[0-9a-f]{40,64}", text, flags=re.I)
        )
    if path == "/.env":
        return status in {200, 206} and _looks_like_env(sample)
    if path == "/server-status":
        low = sample.lower()
        markers = ("apache server status", "server version:", "server uptime:")
        return status in {200, 206} and any(marker in low for marker in markers)
    return False


def _looks_like_env(sample: str) -> bool:
    assignments = 0
    for line in (sample or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_.-]*\s*=", stripped):
            assignments += 1
    return assignments > 0
