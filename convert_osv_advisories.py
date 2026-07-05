#!/usr/bin/env python3
"""
Convert OSV bulk ZIP files or directories to the custom
vendor/distribution advisory importer format.

Examples:

  python convert_osv_advisories.py \
    --input https://storage.googleapis.com/osv-vulnerabilities/Ubuntu/all.zip \
    --ecosystem-prefix Ubuntu \
    --output ubuntu-advisories.json

  python convert_osv_advisories.py \
    --input https://storage.googleapis.com/osv-vulnerabilities/Debian/all.zip \
    --ecosystem-prefix Debian \
    --output debian-advisories.json

  python convert_osv_advisories.py \
    --input ubuntu-all.zip debian-all.zip \
    --output linux-advisories.json

By default, only entries with a known fixed version are emitted.
Use --include-unfixed to retain affected entries without a fixed version.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Iterable, Iterator

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def iter_json_documents(source: str) -> Iterator[dict[str, Any]]:
    """Yield JSON objects from a URL, ZIP file, JSON file, or directory."""
    if source.startswith(("https://", "http://")):
        request = urllib.request.Request(
            source,
            headers={"User-Agent": "vendor-distribution-advisory-converter/1.0"},
        )
        with urllib.request.urlopen(request, timeout=120) as response:
            data = response.read()
        yield from iter_bytes(data, source)
        return

    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"Input does not exist: {source}")

    if path.is_dir():
        for json_path in sorted(path.rglob("*.json")):
            try:
                with json_path.open("r", encoding="utf-8") as handle:
                    value = json.load(handle)
                yield from normalize_json_value(value)
            except (OSError, json.JSONDecodeError) as exc:
                print(f"warning: skipping {json_path}: {exc}", file=sys.stderr)
        return

    data = path.read_bytes()
    yield from iter_bytes(data, source)


def iter_bytes(data: bytes, source_name: str) -> Iterator[dict[str, Any]]:
    """Parse ZIP or plain JSON bytes."""
    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in sorted(archive.namelist()):
                if not member.lower().endswith(".json") or member.endswith("/"):
                    continue
                try:
                    with archive.open(member) as handle:
                        value = json.load(io.TextIOWrapper(handle, encoding="utf-8"))
                    yield from normalize_json_value(value)
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    print(
                        f"warning: skipping {source_name}:{member}: {exc}",
                        file=sys.stderr,
                    )
        return

    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Input is neither a ZIP nor valid JSON: {source_name}") from exc

    yield from normalize_json_value(value)


def normalize_json_value(value: Any) -> Iterator[dict[str, Any]]:
    """Accept one OSV object, an array of OSV objects, or common wrappers."""
    if isinstance(value, dict):
        if isinstance(value.get("vulns"), list):
            for item in value["vulns"]:
                if isinstance(item, dict):
                    yield item
        else:
            yield value
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                yield item


def collect_cve_ids(record: dict[str, Any], affected: dict[str, Any]) -> list[str]:
    """Collect CVE IDs from common OSV and distro-specific locations."""
    candidates: list[Any] = []

    for key in ("id", "aliases", "upstream", "related"):
        value = record.get(key)
        if isinstance(value, list):
            candidates.extend(value)
        else:
            candidates.append(value)

    for container in (
        record.get("database_specific"),
        affected.get("database_specific"),
        affected.get("ecosystem_specific"),
    ):
        if not isinstance(container, dict):
            continue

        cves_map = container.get("cves_map")
        if isinstance(cves_map, dict):
            cves = cves_map.get("cves")
            if isinstance(cves, list):
                for cve in cves:
                    if isinstance(cve, dict):
                        candidates.append(cve.get("id"))
                    else:
                        candidates.append(cve)

        cves = container.get("cves")
        if isinstance(cves, list):
            for cve in cves:
                if isinstance(cve, dict):
                    candidates.append(cve.get("id"))
                else:
                    candidates.append(cve)

    result = {
        str(value).upper()
        for value in candidates
        if isinstance(value, str) and CVE_RE.fullmatch(value.strip())
    }
    return sorted(result)


def collect_fixed_versions(affected: dict[str, Any]) -> list[str]:
    fixed_versions: list[str] = []
    ranges = affected.get("ranges")
    if not isinstance(ranges, list):
        return fixed_versions

    for range_item in ranges:
        if not isinstance(range_item, dict):
            continue
        events = range_item.get("events")
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, dict):
                continue
            fixed = event.get("fixed")
            if isinstance(fixed, str) and fixed.strip():
                fixed_versions.append(fixed.strip())

    return sorted(set(fixed_versions))


def format_distribution(ecosystem: str, keep_raw: bool) -> str:
    """
    Preserve the release because fixed versions are release-specific.

    Examples:
      Ubuntu:22.04:LTS -> Ubuntu 22.04 LTS
      Ubuntu:Pro:18.04:LTS -> Ubuntu Pro 18.04 LTS
      Debian:12 -> Debian 12
      Alpine:v3.22 -> Alpine 3.22
    """
    if keep_raw:
        return ecosystem

    parts = ecosystem.split(":")
    base = parts[0].strip()
    suffix = [part.strip() for part in parts[1:] if part.strip()]

    if base == "Alpine" and suffix:
        suffix[0] = suffix[0].removeprefix("v")

    return " ".join([base, *suffix]).strip()


def select_reference(record: dict[str, Any]) -> str:
    references = record.get("references")
    urls: list[str] = []

    if isinstance(references, list):
        for reference in references:
            if isinstance(reference, dict):
                url = reference.get("url")
                if isinstance(url, str) and url.startswith(("https://", "http://")):
                    urls.append(url)

    preferred_fragments = (
        "ubuntu.com/security/notices/",
        "ubuntu.com/security/CVE-",
        "security-tracker.debian.org/tracker/",
        "security.archlinux.org/",
        "security.alpinelinux.org/",
        "access.redhat.com/errata/",
        "errata.rockylinux.org/",
        "security.almalinux.org/",
    )

    for fragment in preferred_fragments:
        for url in urls:
            if fragment in url:
                return url

    if urls:
        return urls[0]

    record_id = record.get("id")
    if isinstance(record_id, str) and record_id:
        return f"https://osv.dev/vulnerability/{record_id}"

    return "https://osv.dev/"


def package_targets(
    affected: dict[str, Any],
    source_package: str,
    fixed_versions: list[str],
    expand_binaries: bool,
) -> list[tuple[str, list[str]]]:
    """Return source-package or binary-package targets for matching."""
    if not expand_binaries:
        return [(source_package, fixed_versions)]

    ecosystem_specific = affected.get("ecosystem_specific")
    binaries = (
        ecosystem_specific.get("binaries")
        if isinstance(ecosystem_specific, dict)
        else None
    )
    if not isinstance(binaries, list) or not binaries:
        return [(source_package, fixed_versions)]

    targets: list[tuple[str, list[str]]] = []
    for binary in binaries:
        if isinstance(binary, str) and binary.strip():
            targets.append((binary.strip(), fixed_versions))
            continue

        if not isinstance(binary, dict):
            continue

        name = binary.get("binary_name") or binary.get("name")
        version = binary.get("binary_version") or binary.get("version")
        if not isinstance(name, str) or not name.strip():
            continue

        versions = (
            [version.strip()]
            if isinstance(version, str) and version.strip()
            else fixed_versions
        )
        targets.append((name.strip(), versions))

    return targets or [(source_package, fixed_versions)]


def convert_record(
    record: dict[str, Any],
    ecosystem_prefixes: tuple[str, ...],
    include_unfixed: bool,
    raw_distribution: bool,
    expand_binaries: bool,
    distribution_name: str | None,
) -> Iterator[dict[str, Any]]:
    affected_items = record.get("affected")
    if not isinstance(affected_items, list):
        return

    for affected in affected_items:
        if not isinstance(affected, dict):
            continue

        package = affected.get("package")
        if not isinstance(package, dict):
            continue

        ecosystem = package.get("ecosystem")
        package_name = package.get("name")

        if not isinstance(ecosystem, str) or not isinstance(package_name, str):
            continue

        if ecosystem_prefixes and not any(
            ecosystem == prefix or ecosystem.startswith(prefix + ":")
            for prefix in ecosystem_prefixes
        ):
            continue

        cve_ids = collect_cve_ids(record, affected)
        if not cve_ids:
            continue

        fixed_versions = collect_fixed_versions(affected)
        reference_url = select_reference(record)
        distribution = (
            distribution_name
            if distribution_name
            else format_distribution(ecosystem, raw_distribution)
        )

        targets = package_targets(
            affected=affected,
            source_package=package_name,
            fixed_versions=fixed_versions,
            expand_binaries=expand_binaries,
        )

        if fixed_versions:
            for target_package, target_versions in targets:
                for cve_id in cve_ids:
                    for fixed_version in target_versions:
                        yield {
                            "cve_id": cve_id,
                            "distribution": distribution,
                            "package": target_package,
                            "fixed_version": fixed_version,
                            "status": "fixed",
                            "reference_url": reference_url,
                        }
        elif include_unfixed:
            for target_package, _ in targets:
                for cve_id in cve_ids:
                    yield {
                        "cve_id": cve_id,
                        "distribution": distribution,
                        "package": target_package,
                        "fixed_version": None,
                        "status": "affected",
                        "reference_url": reference_url,
                    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert OSV vulnerability data to vendor/distribution advisory JSON."
    )
    parser.add_argument(
        "--input",
        nargs="+",
        required=True,
        help="OSV ZIP/JSON URL, local ZIP/JSON file, or directory.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON path.",
    )
    parser.add_argument(
        "--source",
        default="osv-bulk",
        help='Top-level source value. Default: "osv-bulk".',
    )
    parser.add_argument(
        "--ecosystem-prefix",
        action="append",
        default=[],
        help="Filter by ecosystem prefix, e.g. Ubuntu, Debian, Alpine. Repeatable.",
    )
    parser.add_argument(
        "--include-unfixed",
        action="store_true",
        help="Include affected entries without a known fixed version.",
    )
    parser.add_argument(
        "--raw-distribution",
        action="store_true",
        help='Keep OSV ecosystem strings unchanged, e.g. "Ubuntu:22.04:LTS".',
    )
    parser.add_argument(
        "--distribution-name",
        help=(
            'Override every output distribution value, e.g. "Ubuntu". '
            "Use only when the input is filtered to one distro release."
        ),
    )
    parser.add_argument(
        "--expand-binaries",
        action="store_true",
        help=(
            "Use distro binary package names when OSV provides them "
            "(for example openssh-server instead of source package openssh)."
        ),
    )
    parser.add_argument(
        "--top-level-array",
        action="store_true",
        help="Write a bare array instead of {source, advisories}.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    prefixes = tuple(args.ecosystem_prefix)

    rows: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    for source in args.input:
        for record in iter_json_documents(source):
            for row in convert_record(
                record=record,
                ecosystem_prefixes=prefixes,
                include_unfixed=args.include_unfixed,
                raw_distribution=args.raw_distribution,
                expand_binaries=args.expand_binaries,
                distribution_name=args.distribution_name,
            ):
                key = (
                    row["cve_id"],
                    row["distribution"],
                    row["package"],
                    row["fixed_version"],
                    row["status"],
                    row["reference_url"],
                )
                if key not in seen:
                    seen.add(key)
                    rows.append(row)

    rows.sort(
        key=lambda item: (
            item["distribution"],
            item["package"],
            item["cve_id"],
            item["fixed_version"] or "",
        )
    )

    output_value: Any
    if args.top_level_array:
        output_value = rows
    else:
        output_value = {
            "source": args.source,
            "advisories": rows,
        }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(output_value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Wrote {len(rows)} advisories to {output_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
