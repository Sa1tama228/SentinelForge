"""Product normalization for vulnerability correlation."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_ALIASES_PATH = Path(__file__).with_name("product_aliases.json")


@dataclass(frozen=True)
class ProductCandidate:
    vendor: str
    product: str
    display_name: str
    cpe_uri: str
    confidence: float
    matched_alias: str
    source: str = "alias-db"


def normalize_product(raw_product: str, *, raw_service: str = "") -> list[ProductCandidate]:
    """Return canonical product candidates ordered by confidence.

    The function is intentionally conservative: an unknown product returns an
    empty list rather than inventing a CPE.
    """
    tokens = _candidate_tokens(raw_product, raw_service)
    out: list[ProductCandidate] = []
    seen: set[str] = set()
    aliases = _alias_index()
    for token in tokens:
        entry = aliases.get(token)
        if not entry:
            continue
        for cpe in entry.get("cpe_candidates", []):
            key = f"{entry['vendor']}:{entry['product']}:{cpe}"
            if key in seen:
                continue
            seen.add(key)
            out.append(
                ProductCandidate(
                    vendor=entry["vendor"],
                    product=entry["product"],
                    display_name=entry.get("display_name") or entry["product"],
                    cpe_uri=cpe,
                    confidence=float(entry.get("confidence", 0.5)),
                    matched_alias=token,
                )
            )
    out.sort(key=lambda item: item.confidence, reverse=True)
    return out


def alias_schema_version() -> int:
    return int(_alias_db().get("schema_version", 0))


def _candidate_tokens(raw_product: str, raw_service: str) -> list[str]:
    values = []
    for value in (raw_product, raw_service):
        cleaned = _clean(value)
        if cleaned:
            values.append(cleaned)
            first = cleaned.split(" ", 1)[0]
            if first and first != cleaned:
                values.append(first)
    return list(dict.fromkeys(values))


def _clean(value: str) -> str:
    value = (value or "").lower().strip()
    value = re.sub(r"[/_]+", " ", value)
    value = re.sub(r"\b\d+(?:\.\d+)+[a-z0-9.+~-]*\b", " ", value)
    value = re.sub(r"[^a-z0-9.+-]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


@lru_cache(maxsize=1)
def _alias_db() -> dict:
    return json.loads(_ALIASES_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _alias_index() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for entry in _alias_db().get("aliases", []):
        for alias in entry.get("aliases", []):
            out[_clean(alias)] = entry
    return out
