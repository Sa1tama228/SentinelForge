from __future__ import annotations

import json
import urllib.request

from ...core import net


def lookup(domain: str, timeout: float = 10.0) -> dict:
    url = f"https://rdap.org/domain/{domain}"
    req = urllib.request.Request(
        url, headers={"User-Agent": "SentinelForge-Recon/0.1", "Accept": "application/rdap+json"}
    )
    try:
        with net.opener(url).open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:
        return {"error": str(exc)}

    registrar = ""
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            registrar = ent.get("vcardArray", ["", []])[1]
            registrar = _flatten_vcard(registrar) or ent.get("handle", "")
            break

    events = {e.get("eventAction"): e.get("eventDate")
              for e in data.get("events", [])}
    return {
        "status": data.get("status", []),
        "registrar": registrar,
        "registered": events.get("registration"),
        "updated": events.get("last changed"),
        "expires": events.get("expiration"),
        "nameservers": [n.get("ldhName") for n in data.get("nameservers", [])],
    }


def _flatten_vcard(vcard: list) -> str:
    if not isinstance(vcard, list):
        return ""
    for entry in vcard:
        if isinstance(entry, list) and entry and entry[0] == "fn":
            return entry[3] if len(entry) > 3 else ""
    return ""
