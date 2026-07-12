from __future__ import annotations


def diff_lists(previous: list[str], current: list[str]) -> dict:
    prev = set(previous or [])
    cur = set(current or [])
    return {
        "added": sorted(cur - prev),
        "removed": sorted(prev - cur),
        "unchanged": len(prev & cur),
    }


def diff_dns(previous: dict, current: dict) -> dict:
    record_types = sorted((set(previous or {}) | set(current or {})) - {"posture"})
    changed = {}
    for rtype in record_types:
        delta = diff_lists(previous.get(rtype, []), current.get(rtype, []))
        if delta["added"] or delta["removed"]:
            changed[rtype] = delta
    return changed


def diff_technologies(previous: dict, current: dict) -> dict:
    return diff_lists(previous.get("technologies", []), current.get("technologies", []))
