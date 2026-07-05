"""Safe HTTP exposure checks for common files/endpoints."""
from __future__ import annotations

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
    base = domain if domain.startswith("http") else "https://" + domain
    results = []
    for path, (severity, title) in CHECKS.items():
        url = base.rstrip("/") + path
        status, sample, final_url = _head_or_get(url, ua=ua, timeout=timeout)
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


def _head_or_get(url: str, *, ua: str, timeout: float) -> tuple[int | None, str, str]:
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": ua})
    try:
        with net.opener(url).open(req, timeout=timeout) as resp:
            return resp.status, "", resp.geturl()
    except urllib.error.HTTPError as exc:
        if exc.code not in {405, 403, 401, 200}:
            return exc.code, "", url
    except Exception:
        return None, "", url
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
        return status == 200 or "ref:" in sample.lower()
    if path == "/.env":
        low = sample.lower()
        return status == 200 and ("=" in sample or "secret" in low or "password" in low)
    if path == "/server-status":
        return status in {200, 401, 403}
    return False
