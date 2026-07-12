from __future__ import annotations

from dataclasses import dataclass

from ....core import db
from .product_normalizer import normalize_product


@dataclass(frozen=True)
class CPECandidate:
    cpe_uri: str
    vendor: str
    product: str
    display_name: str
    confidence: float
    reason: str


def candidates_for(raw_product: str, *, raw_service: str = "") -> list[CPECandidate]:
    candidates: list[CPECandidate] = []
    seen: set[str] = set()
    for override in db.cpe_product_overrides(_cache_lookup_token(raw_product) or raw_product):
        # Human-reviewed overrides win because product banners often do not
        # match official CPE vendor/product names.
        seen.add(override["cpe_uri"])
        candidates.append(
            CPECandidate(
                cpe_uri=override["cpe_uri"],
                vendor=override["vendor"],
                product=override["product"],
                display_name=f"{override['vendor']}:{override['product']}",
                confidence=float(override["confidence"] or 0.99),
                reason="reviewed CPE mapping override",
            )
        )
    normalized = normalize_product(raw_product, raw_service=raw_service)
    for product in normalized:
        seen.add(product.cpe_uri)
        candidates.append(
            CPECandidate(
                cpe_uri=product.cpe_uri,
                vendor=product.vendor,
                product=product.product,
                display_name=product.display_name,
                confidence=product.confidence,
                reason=f"alias '{product.matched_alias}' matched local product alias database",
            )
        )
        for cached in db.cpe_products_for_product(product.product, vendor=product.vendor, limit=20):
            if cached["cpe_uri"] in seen:
                continue
            # Cached rows are useful enrichment, but weaker than the alias that
            # directly matched the observed product.
            seen.add(cached["cpe_uri"])
            candidates.append(
                CPECandidate(
                    cpe_uri=cached["cpe_uri"],
                    vendor=cached["vendor"],
                    product=cached["product"],
                    display_name=cached["title"] or f"{cached['vendor']}:{cached['product']}",
                    confidence=max(0.5, product.confidence - 0.08),
                    reason="local CPE cache exact vendor/product match",
                )
            )
    if not normalized:
        token = _cache_lookup_token(raw_product) or _cache_lookup_token(raw_service)
        for cached in db.cpe_products_for_product(token, limit=20):
            if cached["cpe_uri"] in seen:
                continue
            # Last-resort token matches stay modest confidence so later scoring
            # does not treat them like reviewed mappings.
            seen.add(cached["cpe_uri"])
            candidates.append(
                CPECandidate(
                    cpe_uri=cached["cpe_uri"],
                    vendor=cached["vendor"],
                    product=cached["product"],
                    display_name=cached["title"] or f"{cached['vendor']}:{cached['product']}",
                    confidence=0.56,
                    reason="local CPE cache exact product-name match",
                )
            )
    return sorted(candidates, key=lambda item: item.confidence, reverse=True)


def _cache_lookup_token(value: str) -> str:
    token = (value or "").strip().lower()
    if not token:
        return ""
    token = token.split("/", 1)[0].split(" ", 1)[0]
    return token.replace("-", "_")
