"""Optional Nikto web-audit integration.

Nikto is an external Perl tool. SentinelForge treats its output as supporting
web-audit evidence, not as confirmed exploitation proof.
"""
from __future__ import annotations

import csv
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from ...core import config

WEB_SERVICES = {"http", "https", "http-proxy", "http-alt"}


def available(path_value: str = "") -> bool:
    return _command(path_value) is not None


def status(path_value: str = "") -> str:
    if shutil.which("nikto"):
        return "available on PATH"
    local = _local_script(path_value)
    if local and _perl_command():
        return f"available via Perl: {local}"
    if local:
        return f"installed at {local}, but Perl is not on PATH"
    return "not found"


def run(target: str, port: int, *, service: str = "", timeout: int = 120,
        path_value: str = "", tuning: str = "", max_findings: int = 25) -> dict:
    cmd = _command(path_value)
    if cmd is None:
        return {"ok": False, "error": "Nikto not found", "findings": []}
    url = _target_url(target, port, service)
    with tempfile.TemporaryDirectory(prefix="sentinelforge-nikto-") as tmp:
        out_path = Path(tmp) / "nikto.csv"
        args = [
            *cmd,
            "-host",
            url,
            "-Format",
            "csv",
            "-output",
            str(out_path),
            "-nointeractive",
        ]
        if tuning.strip():
            args.extend(["-Tuning", tuning.strip()])
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(10, int(timeout)),
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "Nikto timed out", "findings": []}
        except OSError as exc:
            return {"ok": False, "error": str(exc), "findings": []}
        findings = _parse_csv(out_path, max_findings=max_findings)
        if not findings:
            findings = _parse_stdout(proc.stdout, max_findings=max_findings)
        return {
            "ok": proc.returncode in {0, 1, 2} or bool(findings),
            "returncode": proc.returncode,
            "target": url,
            "stdout_tail": proc.stdout[-2000:],
            "stderr_tail": proc.stderr[-2000:],
            "findings": findings[:max_findings],
        }


def _command(path_value: str = "") -> list[str] | None:
    local = _local_script(path_value)
    if local:
        perl = _perl_command()
        if local.suffix.lower() == ".pl":
            return [perl, str(local)] if perl else None
        return [str(local)]
    direct = shutil.which("nikto")
    return [direct] if direct else None


def _local_script(path_value: str = "") -> Path | None:
    candidates = []
    if path_value.strip():
        candidates.append(Path(path_value).expanduser())
    root = config.ROOT
    candidates.extend(
        [
            root / "tools" / "nikto" / "program" / "nikto.pl",
            root / "tools" / "nikto" / "nikto.pl",
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _perl_command() -> str | None:
    direct = shutil.which("perl")
    if direct:
        return direct
    for candidate in (
        Path("C:/Strawberry/perl/bin/perl.exe"),
        Path("C:/Program Files/Strawberry/perl/bin/perl.exe"),
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def _target_url(target: str, port: int, service: str) -> str:
    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        if parsed.port:
            return target
        scheme = parsed.scheme
        netloc = f"{parsed.hostname}:{port}" if port not in {80, 443} else parsed.hostname
        return f"{scheme}://{netloc or target}"
    scheme = "https" if port == 443 or service == "https" else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{target}"
    return f"{scheme}://{target}:{port}"


def _parse_csv(path: Path, *, max_findings: int) -> list[dict]:
    if not path.is_file():
        return []
    findings = []
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            sample = fh.read(4096)
            fh.seek(0)
            has_header = "OSVDB" in sample or "host" in sample.lower() or "description" in sample.lower()
            reader = csv.DictReader(fh) if has_header else csv.reader(fh)
            for row in reader:
                item = _row_to_finding(row)
                if item:
                    findings.append(item)
                if len(findings) >= max_findings:
                    break
    except (OSError, csv.Error):
        return []
    return findings


def _row_to_finding(row) -> dict:
    if isinstance(row, dict):
        lowered = {str(k).strip().lower(): str(v).strip() for k, v in row.items()}
        description = (
            lowered.get("description")
            or lowered.get("msg")
            or lowered.get("message")
            or lowered.get("finding")
            or lowered.get("item")
            or ""
        )
        uri = lowered.get("uri") or lowered.get("url") or lowered.get("path") or ""
        osvdb = lowered.get("osvdb") or lowered.get("id") or ""
        method = lowered.get("method") or ""
    else:
        cells = [str(value).strip() for value in row]
        if len(cells) < 2:
            return {}
        description = max(cells, key=len)
        uri = next((cell for cell in cells if cell.startswith("/")), "")
        osvdb = next((cell for cell in cells if cell.upper().startswith("OSVDB") or cell.isdigit()), "")
        method = ""
    if not description or description.lower().startswith("nikto"):
        return {}
    return {
        "title": description[:180],
        "uri": uri,
        "method": method,
        "osvdb": osvdb,
        "severity": _severity_for(description),
        "confidence": "Low",
        "source": "nikto",
    }


def _parse_stdout(stdout: str, *, max_findings: int) -> list[dict]:
    findings = []
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line.startswith("+ "):
            continue
        text = line[2:].strip()
        if not text or text.lower().startswith(("target", "start time", "end time")):
            continue
        findings.append(
            {
                "title": text[:180],
                "uri": "",
                "method": "",
                "osvdb": "",
                "severity": _severity_for(text),
                "confidence": "Low",
                "source": "nikto",
            }
        )
        if len(findings) >= max_findings:
            break
    return findings


def _severity_for(text: str) -> str:
    low = text.lower()
    if any(token in low for token in ("remote command", "rce", "shell", "password file", ".env", ".git", "sql injection")):
        return "High"
    if any(token in low for token in ("x-frame", "x-content-type", "httponly", "cookie", "header", "directory indexing")):
        return "Low"
    return "Medium"
