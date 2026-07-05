"""Scanner profile definitions.

Profiles keep the UI and runner aligned without hiding the actual requested
ports. They are conservative presets for authorized scanning only.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    key: str
    label: str
    ports: str
    include_udp: bool = False
    low_rate: bool = False


PROFILES: dict[str, ScanProfile] = {
    "custom": ScanProfile("custom", "Custom", ""),
    "fast": ScanProfile("fast", "Fast top ports", "21,22,25,53,80,110,143,443,445,3306,3389,5432,5900,8080,8443"),
    "web": ScanProfile("web", "Web-focused", "80,443,8000,8080,8081,8443,8888"),
    "internal": ScanProfile(
        "internal",
        "Internal network",
        "21,22,23,25,53,80,88,110,135,139,143,389,443,445,464,587,636,993,995,1433,1521,3306,3389,5432,5900,5985,5986,6379,8080,8443,9200,9300,27017",
        include_udp=True,
    ),
    "full-tcp": ScanProfile("full-tcp", "Full TCP", "1-65535", low_rate=True),
    "low-rate": ScanProfile("low-rate", "Low-rate", "21,22,25,53,80,110,143,443,445,3389,8080", low_rate=True),
}


def profile_options() -> list[tuple[str, str]]:
    return [(profile.key, profile.label) for profile in PROFILES.values()]


def resolve_profile(key: str, custom_ports: str) -> ScanProfile:
    profile = PROFILES.get((key or "custom").strip().lower(), PROFILES["custom"])
    if profile.key == "custom":
        return ScanProfile("custom", "Custom", custom_ports)
    return profile
