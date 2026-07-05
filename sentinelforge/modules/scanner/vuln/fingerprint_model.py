"""Structured service fingerprint extraction for CVE exposure assessment."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .. import fingerprint
from .product_normalizer import normalize_product


@dataclass(frozen=True)
class ServiceFingerprint:
    vendor: str
    product: str
    version: str
    distribution: str
    package_revision: str
    protocol: str
    confidence: float
    detection_method: str
    service: str
    raw_service: str
    raw_version: str

    def as_dict(self) -> dict:
        return asdict(self)


def from_scan_result(port: int, proto: str, banner: str) -> ServiceFingerprint:
    service, raw_version = fingerprint.identify(port, banner)
    product_name = _product_from_version(raw_version) or service
    candidates = normalize_product(product_name, raw_service=service)
    vendor = candidates[0].vendor if candidates else ""
    product = candidates[0].product if candidates else product_name.lower().replace(" ", "_")
    version = _version_from_text(raw_version)
    distribution, package_revision = _distribution_bits(f"{raw_version} {banner}")
    confidence = _confidence(service, raw_version, candidates, banner)
    return ServiceFingerprint(
        vendor=vendor,
        product=product,
        version=version,
        distribution=distribution,
        package_revision=package_revision,
        protocol=proto,
        confidence=confidence,
        detection_method=_method_for_banner(port, banner),
        service=service,
        raw_service=service,
        raw_version=raw_version,
    )


def _product_from_version(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    token = re.split(r"[\s/]+", text, 1)[0]
    return token.strip()


def _version_from_text(value: str) -> str:
    match = re.search(r"(\d+(?:[._-]\d+)*(?:[a-z][a-z0-9.]*)?(?:[+~:-][a-z0-9.+:~_-]+)?)", value or "", re.I)
    return match.group(1) if match else ""


def _distribution_bits(value: str) -> tuple[str, str]:
    low = (value or "").lower()
    distribution = ""
    if "ubuntu" in low:
        distribution = "Ubuntu"
    elif "debian" in low:
        distribution = "Debian"
    elif "red hat" in low or "rhel" in low:
        distribution = "Red Hat"
    elif "centos" in low:
        distribution = "CentOS"
    package_revision = ""
    match = re.search(r"\b(\d+(?:ubuntu|deb|el|rhel|centos)[\w.+:~-]*)\b", low)
    if match:
        package_revision = match.group(1)
    return distribution, package_revision


def _confidence(service: str, raw_version: str, candidates: list, banner: str) -> float:
    score = 0.25
    if service and service != "unknown":
        score += 0.2
    if raw_version:
        score += 0.25
    if candidates:
        score += min(0.2, candidates[0].confidence * 0.2)
    if banner and "[scan]" not in banner:
        score += 0.1
    return round(min(score, 0.98), 2)


def _method_for_banner(port: int, banner: str) -> str:
    low = (banner or "").lower()
    if "tls cert" in low:
        return "tls-http-probe"
    if low.startswith("http/") or "server:" in low:
        return "http-head-probe"
    if banner:
        return "tcp-banner"
    return f"port-{port}-inference"
