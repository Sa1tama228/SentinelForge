"""Conservative version comparison and affected-range evaluation."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

try:
    from packaging.version import InvalidVersion, Version
except Exception:  # pragma: no cover - packaging is expected but optional
    InvalidVersion = Exception
    Version = None


class MatchResult(str, Enum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class VersionRange:
    start_including: str = ""
    start_excluding: str = ""
    end_including: str = ""
    end_excluding: str = ""
    exact: str = ""


def evaluate_range(version: str, version_range: VersionRange) -> MatchResult:
    parsed = _parse(version)
    if parsed is None:
        return MatchResult.UNKNOWN
    if version_range.exact:
        exact = _parse(version_range.exact)
        if exact is None:
            return MatchResult.UNKNOWN
        cmp = _compare_parsed(parsed, exact)
        return MatchResult.VULNERABLE if cmp == 0 else MatchResult.NOT_VULNERABLE
    checks = [
        (version_range.start_including, lambda c: c >= 0),
        (version_range.start_excluding, lambda c: c > 0),
        (version_range.end_including, lambda c: c <= 0),
        (version_range.end_excluding, lambda c: c < 0),
    ]
    for bound, predicate in checks:
        if not bound:
            continue
        parsed_bound = _parse(bound)
        if parsed_bound is None:
            return MatchResult.UNKNOWN
        if not predicate(_compare_parsed(parsed, parsed_bound)):
            return MatchResult.NOT_VULNERABLE
    return MatchResult.VULNERABLE


def compare_versions(left: str, right: str) -> int | None:
    parsed_left = _parse(left)
    parsed_right = _parse(right)
    if parsed_left is None or parsed_right is None:
        return None
    return _compare_parsed(parsed_left, parsed_right)


def _parse(value: str):
    raw = (value or "").strip()
    if not raw:
        return None
    token = _extract_version_token(raw)
    if not token:
        return None
    if Version is not None:
        try:
            return ("packaging", Version(_normalize_for_packaging(token)))
        except InvalidVersion:
            pass
    parts = _numeric_parts(token)
    if not parts:
        return None
    suffix = _suffix_rank(token)
    return ("numeric", tuple(parts), suffix)


def _extract_version_token(value: str) -> str:
    match = re.search(r"(?<![a-z0-9])(\d+(?:[._-]\d+)*(?:[a-z][a-z0-9.]*)?(?:[+~:-][a-z0-9.+:~_-]+)?)", value, re.I)
    return match.group(1) if match else ""


def _normalize_for_packaging(token: str) -> str:
    token = token.replace("_", ".")
    token = re.sub(r"(?<=\d)p(?=\d)", ".post", token)
    if ":" in token:
        token = token.split(":", 1)[1]
    token = token.replace("~", ".dev")
    return token


def _numeric_parts(token: str) -> list[int]:
    return [int(p) for p in re.findall(r"\d+", token)]


def _suffix_rank(token: str) -> tuple:
    # Keeps OpenSSH-like 8.9p1 distinct from 8.9 while remaining comparable.
    suffixes = re.findall(r"([a-z]+)(\d*)", token.lower())
    ranked = []
    for name, number in suffixes:
        if name.isdigit():
            continue
        ranked.append((name, int(number or 0)))
    return tuple(ranked)


def _compare_parsed(left, right) -> int:
    if left[0] == "packaging" and right[0] == "packaging":
        return (left[1] > right[1]) - (left[1] < right[1])
    left_parts = left[1] if left[0] == "numeric" else _numeric_parts(str(left[1]))
    right_parts = right[1] if right[0] == "numeric" else _numeric_parts(str(right[1]))
    max_len = max(len(left_parts), len(right_parts))
    l_tuple = tuple(left_parts) + (0,) * (max_len - len(left_parts))
    r_tuple = tuple(right_parts) + (0,) * (max_len - len(right_parts))
    if l_tuple != r_tuple:
        return (l_tuple > r_tuple) - (l_tuple < r_tuple)
    left_suffix = left[2] if left[0] == "numeric" else ()
    right_suffix = right[2] if right[0] == "numeric" else ()
    return (left_suffix > right_suffix) - (left_suffix < right_suffix)
