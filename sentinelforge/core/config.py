from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# Project root = parent of the 'sentinelforge' package dir.
ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("SF_DATA_DIR", ROOT / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

CONFIG_PATH = DATA_DIR / "config.json"

DEFAULTS: dict[str, Any] = {
    "db_path": str(DATA_DIR / "sentinelforge.db"),
    "honeypot": {
        "http_port": 8080,
        "ssh_port": 2222,
        "ftp_port": 2121,
        "telnet_port": 2323,
        "smtp_port": 2525,
        "enabled": {"http": True, "ssh": True, "ftp": False, "telnet": False, "smtp": False},
        "http_html_path": "",
        "http_tls_cert_path": "",
        "http_tls_key_path": "",
        "persona": "apache_ubuntu",
        "persona_tags": ["linux", "ubuntu", "apache", "php"],
        "http_server_header": "Apache/2.4.52 (Ubuntu)",
        "http_status": "200 OK",
        "http_content_type": "text/html; charset=utf-8",
        "http_extra_headers": {
            "X-Powered-By": "PHP/8.1.2",
            "X-Generator": "WordPress 6.4.3",
        },
        "http_login_enabled": True,
        "http_login_paths": ["/login", "/admin", "/wp-login.php"],
        "http_login_title": "Sign in",
        "http_login_html_path": "",
        "http_routes": [
            {"path": "/server-status", "status": "403 Forbidden", "content_type": "text/html", "body": "<h1>Forbidden</h1>"},
            {"path": "/phpmyadmin", "status": "401 Unauthorized", "content_type": "text/html", "body": "<h1>phpMyAdmin</h1><form method='post'><input name='pma_username'><input name='pma_password' type='password'><button>Go</button></form>"},
        ],
        "http_body": (
            "<!doctype html><html><head><title>Apache2 Ubuntu Default Page: It works</title></head>"
            "<body><h1>It works!</h1><p>This is the default welcome page for Apache2.</p></body></html>"
        ),
        "ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        "ftp_banner": "220 (vsFTPd 3.0.5)",
        "ftp_user_reply": "331 Please specify the password.",
        "ftp_pass_reply": "530 Login incorrect.",
        "telnet_banner": "Ubuntu 22.04 LTS",
        "telnet_login_prompt": "login: ",
        "telnet_password_prompt": "Password: ",
        "telnet_fail_reply": "Login incorrect",
        "smtp_banner": "220 mail.local ESMTP Postfix",
        "smtp_ehlo_reply": "250-mail.local\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 AUTH LOGIN PLAIN",
        "smtp_relay_denied": "554 5.7.1 Relay access denied",
        "geoip_enabled": False,
        "geoip_db_path": "",
        "alert_sound_enabled": True,
        "alert_sound_path": str(ROOT / "sounds" / "HoneyPot_warning.mp3"),
        "credential_storage": "redacted",
    },
    "scanner": {
        "default_ports": "21,22,23,25,53,80,110,143,443,445,1433,3306,3389,5432,5900,8080,8443",
        "timeout_sec": 1.5,
        "max_threads": 200,
        "low_rate_max_threads": 25,
        "engine": "auto",
        "nmap_extra_flags": "",
        "nikto_enabled": False,
        "nikto_path": "",
        "nikto_timeout_sec": 120,
        "nikto_tuning": "",
        "nikto_max_findings": 25,
        "host_probe": "auto",
        "default_profile": "custom",
        "udp_light_enabled": False,
        "vulnerability_check_default": False,
        "seed_demo_cache_on_scan": True,
        "minimum_candidate_confidence": 0.35,
        "include_unknown_version_candidates": False,
        "max_vulnerability_matches_per_service": 25,
        "target_allowlist": [],
        "scope_file_path": "",
        "block_public_targets": True,
        "block_private_targets": False,
        "max_concurrent_scans": 3,
        "source_sync_interval_hours": 24,
        "nvd_json_path": "",
        "cisa_kev_path": "",
        "epss_csv_path": "",
        "exploitdb_csv_path": "",
        "vendor_advisory_json_path": "",
    },
    "recon": {
        "resolvers": ["1.1.1.1", "8.8.8.8"],
        "user_agent": "SentinelForge-Recon/0.1 (+authorized-use)",
        "http_client": "auto",
        "subdomain_sources": ["crtsh", "hackertarget", "dnsdumpster"],
        "source_timeout_sec": 20,
        "safe_endpoint_checks": True,
        "safe_endpoint_timeout_sec": 5,
        "source_rate_delay_sec": 0.0,
        "wordlist_enabled": False,
        "wordlist_path": "",
        "wordlist_limit": 2000,
        "export_dir": str(DATA_DIR / "exports"),
    },
    "retention": {
        "honeypot_max_events": 50000,
        "scan_history_max_runs": 5000,
    },
    "network": {
        "use_proxy": False,
        "http_proxy": "",
        "https_proxy": "",
        "proxy_list_path": "",
        "proxy_scheme": "http",
        "no_proxy": "127.0.0.1,localhost",
    },
    "ui": {"refresh_sec": 3, "theme": "dark"},
}


def load() -> dict[str, Any]:
    """Load config merged over defaults."""
    cfg = json.loads(json.dumps(DEFAULTS))  # deep copy
    if CONFIG_PATH.exists():
        try:
            stored = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            _deep_merge(cfg, stored)
        except (json.JSONDecodeError, OSError):
            pass
    return cfg


def save(cfg: dict[str, Any]) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> None:
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
