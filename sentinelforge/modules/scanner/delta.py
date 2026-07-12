from __future__ import annotations


def service_delta(previous: list[dict], current: list[dict]) -> dict:
    prev = {_key(item): item for item in previous or []}
    cur = {_key(item): item for item in current or []}
    added = [cur[key] for key in sorted(set(cur) - set(prev))]
    removed = [prev[key] for key in sorted(set(prev) - set(cur))]
    changed = []
    for key in sorted(set(prev) & set(cur)):
        before = prev[key]
        after = cur[key]
        if (before.get("service") or "") != (after.get("service") or "") or (before.get("version") or "") != (after.get("version") or ""):
            changed.append({"before": before, "after": after})
    return {"added": added, "removed": removed, "changed": changed}


def summarize_delta(delta: dict) -> str:
    return (
        f"added={len(delta.get('added', []))}; "
        f"removed={len(delta.get('removed', []))}; "
        f"changed={len(delta.get('changed', []))}"
    )


def _key(item: dict) -> tuple[str, int]:
    return (str(item.get("proto") or "tcp"), int(item.get("port") or 0))
