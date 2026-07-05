"""Safe verification guidance for CVE exposure candidates.

This module intentionally returns non-destructive manual/probe suggestions. It
does not execute exploit code.
"""
from __future__ import annotations


def recommended_steps(service: str, cve_id: str) -> list[str]:
    service = (service or "").lower()
    if service in {"http", "https", "http-proxy", "https-alt"}:
        return [
            "Confirm product and exact version from authenticated admin UI or package inventory.",
            "Check vendor advisory for patched builds and backported fixes.",
            "Use a non-destructive HTTP probe only if the CVE has a supported verification plugin.",
        ]
    if service == "ssh":
        return [
            "Confirm OpenSSH package version and distribution revision on the host.",
            "Check distribution security tracker for backported remediation.",
            "Avoid exploit-based validation; use vendor advisory criteria for exposure review.",
        ]
    return [
        "Confirm product and exact version from host inventory or vendor tooling.",
        "Review advisory applicability and patched version boundaries.",
        "Perform manual verification before treating this candidate as confirmed vulnerability.",
    ]


def warning() -> str:
    return "Manual verification required. SentinelForge correlates exposure evidence and does not automatically exploit targets."
