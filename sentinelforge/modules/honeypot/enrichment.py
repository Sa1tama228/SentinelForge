"""Honeypot event enrichment: classification, IOCs, and optional GeoIP/ASN."""
from __future__ import annotations

import csv
import ipaddress
import json
import re
from functools import lru_cache
from pathlib import Path

from ...core import config

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.I)


def enrich_event(hp_type: str, src_ip: str, method: str, path: str, headers: str, body: str) -> dict:
    text = "\n".join([hp_type, src_ip, method, path, headers, body])
    classification = classify(hp_type, method, path, headers, body)
    iocs = extract_iocs(text)
    iocs["severity"] = severity_for(classification)
    iocs["alerts"] = alert_tags(classification, text)
    iocs["credentials"] = extract_credentials(hp_type, method, path, headers, body)
    iocs["user_agents"] = _header_values(headers, "user_agent")
    return {
        "classification": classification,
        "iocs": iocs,
        "geo": geo_lookup(src_ip),
    }


def classify(hp_type: str, method: str, path: str, headers: str, body: str) -> str:
    low = "\n".join([hp_type, method, path, headers, body]).lower()
    if hp_type in {"telnet", "ftp", "ssh"} and any(k in low for k in ("pass", "password", "user ", "login")):
        return "credential-attempt"
    if hp_type == "smtp" and any(k in low for k in ("mail from:", "rcpt to:", "auth ", "relay")):
        return "mail-relay-probe"
    if hp_type in {"http", "https"}:
        if any(k in low for k in ("/wp-login", "phpmyadmin", "/admin", "/login")):
            return "login-probe"
        if any(k in low for k in ("../", "%2e%2e", "etc/passwd", "cmd=", "powershell", "wget ", "curl ")):
            return "exploit-probe"
        if method.upper() in {"POST", "PUT", "PATCH"}:
            return "write-probe"
    if "nmap" in low or "masscan" in low or "zgrab" in low:
        return "scanner"
    return "connection"


def severity_for(classification: str) -> str:
    return {
        "exploit-probe": "High",
        "credential-attempt": "Medium",
        "mail-relay-probe": "Medium",
        "login-probe": "Medium",
        "write-probe": "Medium",
        "scanner": "Low",
        "connection": "Info",
    }.get(classification, "Info")


def alert_tags(classification: str, text: str) -> list[str]:
    low = text.lower()
    tags = []
    if classification in {"exploit-probe", "credential-attempt", "mail-relay-probe"}:
        tags.append("review")
    if any(token in low for token in ("nmap", "masscan", "zgrab", "sqlmap", "nikto")):
        tags.append("known-scanner")
    if any(token in low for token in ("/.env", "/.git", "etc/passwd", "powershell", "wget ", "curl ")):
        tags.append("suspicious-payload")
    return sorted(set(tags))


def extract_credentials(hp_type: str, method: str, path: str, headers: str, body: str) -> list[dict]:
    out = []
    low_body = body.lower()
    if hp_type in {"telnet", "ftp"} and path:
        out.append({"service": hp_type, "username": path.replace("USER ", "").strip(), "password": "<redacted>"})
    if hp_type in {"http", "https"} and method.upper() == "POST":
        user = _form_value(body, ("username", "user", "login", "email"))
        password_seen = any(key in low_body for key in ("password=", "passwd=", "pwd="))
        if user or password_seen:
            out.append({"service": hp_type, "username": user, "password": "<redacted>" if password_seen else ""})
    if "auth " in "\n".join([headers, body]).lower():
        out.append({"service": hp_type, "username": "", "password": "<redacted>", "mechanism": "auth-command"})
    return out


def _form_value(body: str, keys: tuple[str, ...]) -> str:
    from urllib.parse import parse_qsl

    try:
        pairs = parse_qsl(body or "", keep_blank_values=True)
    except Exception:
        return ""
    lowered = {key.lower(): value for key, value in pairs}
    for key in keys:
        if key in lowered:
            return lowered[key][:120]
    return ""


def _header_values(headers: str, key: str) -> list[str]:
    values = []
    prefix = key.lower() + "="
    for line in (headers or "").splitlines():
        if line.lower().startswith(prefix):
            values.append(line.split("=", 1)[1][:220])
    return values


def extract_iocs(text: str) -> dict:
    ips = []
    for candidate in _IP_RE.findall(text):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        ips.append(candidate)
    return {
        "ips": sorted(set(ips)),
        "urls": sorted(set(_URL_RE.findall(text))),
        "emails": sorted(set(_EMAIL_RE.findall(text))),
        "cves": sorted(set(m.upper() for m in _CVE_RE.findall(text))),
        "hashes": sorted(set(_HASH_RE.findall(text))),
    }


def geo_lookup(ip: str) -> dict:
    hp = config.load().get("honeypot", {})
    if not hp.get("geoip_enabled", False):
        return {}
    db_path = (hp.get("geoip_db_path") or "").strip()
    if not db_path:
        return {}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    for row in _geo_rows(db_path):
        try:
            network = ipaddress.ip_network(row.get("cidr", ""), strict=False)
        except ValueError:
            continue
        if addr in network:
            return {
                "country": row.get("country", ""),
                "region": row.get("region", ""),
                "city": row.get("city", ""),
                "asn": row.get("asn", ""),
                "org": row.get("org", ""),
                "source": Path(db_path).name,
            }
    return {}


@lru_cache(maxsize=4)
def _geo_rows(path_value: str) -> tuple[dict, ...]:
    path = Path(path_value).expanduser()
    if not path.is_file():
        return ()
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return ()
        if isinstance(data, dict):
            data = data.get("networks", [])
        if not isinstance(data, list):
            return ()
        return tuple(row for row in data if isinstance(row, dict))
    rows = []
    try:
        with path.open("r", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                rows.append(row)
    except OSError:
        return ()
    return tuple(rows)
