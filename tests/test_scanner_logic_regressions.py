import hashlib

import pytest

from sentinelforge.core import db
from sentinelforge.modules.recon import exposure, techstack
from sentinelforge.modules.scanner import discovery, protocols, runner
from sentinelforge.modules.scanner.vuln import correlation, sync
from sentinelforge.modules.scanner.vuln.version_matcher import compare_versions


def test_configured_missing_scope_file_blocks_target(monkeypatch, tmp_path):
    missing = tmp_path / "missing-scope.txt"
    monkeypatch.setattr(
        runner.config,
        "load",
        lambda: {
            "scanner": {
                "target_allowlist": [],
                "scope_file_path": str(missing),
                "block_private_targets": False,
                "block_public_targets": False,
            }
        },
    )

    assert "scope file" in runner._target_policy_error("example.com")


def test_configured_empty_scope_file_without_inline_allowlist_blocks_target(monkeypatch, tmp_path):
    scope_file = tmp_path / "empty-scope.txt"
    scope_file.write_text("# no targets yet\n", encoding="utf-8")
    monkeypatch.setattr(
        runner.config,
        "load",
        lambda: {
            "scanner": {
                "target_allowlist": [],
                "scope_file_path": str(scope_file),
                "block_private_targets": False,
                "block_public_targets": False,
            }
        },
    )

    assert "contains no target patterns" in runner._target_policy_error("example.com")


def test_http_crlf_cleanup_preserves_headers_for_metadata():
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.24.0\r\n"
        "Content-Security-Policy: default-src 'self'\r\n"
        "Set-Cookie: session=abc; HttpOnly\r\n"
        "\r\n"
    )

    cleaned = discovery._clean_banner_text(raw)
    metadata = protocols.extract_metadata(80, "http", cleaned)

    assert metadata["server"] == "nginx/1.24.0"
    assert metadata["security_headers"]["Content-Security-Policy"] is True
    assert metadata["cookies"] == ["session"]


def test_version_comparison_preserves_numeric_epoch():
    assert compare_versions("2:1.0", "1:9.9") == 1


def test_valid_domain_starting_with_http_gets_a_scheme(monkeypatch):
    attempts = []

    def fake_fetch(url, timeout, ua):
        attempts.append(url)
        return {"error": "stop after recording URL"}

    monkeypatch.setattr(techstack, "_fetch_and_detect", fake_fetch)

    techstack.detect("httpbin.org")

    assert attempts == ["https://httpbin.org", "http://httpbin.org"]


def test_sensitive_exposure_checks_require_body_evidence():
    assert not exposure._interesting("/.git/HEAD", 200, "<html>home</html>")
    assert exposure._interesting("/.git/HEAD", 200, "ref: refs/heads/main")
    assert not exposure._interesting("/.env", 200, "<html data-id=\"home\">")
    assert exposure._interesting("/.env", 200, "APP_KEY=secret\nDB_HOST=localhost")
    assert not exposure._interesting("/server-status", 403, "Forbidden")
    assert exposure._interesting("/server-status", 200, "Apache Server Status for example.com")


def test_successful_head_is_followed_by_bounded_get(monkeypatch):
    methods = []

    class Response:
        status = 200

        def __init__(self, body=b""):
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def geturl(self):
            return "https://example.com/.env"

        def read(self, limit):
            return self._body[:limit]

    class Opener:
        def open(self, request, timeout):
            methods.append(request.get_method())
            body = b"APP_KEY=secret" if request.get_method() == "GET" else b""
            return Response(body)

    monkeypatch.setattr(exposure.net, "opener", lambda _url: Opener())

    status, sample, _url = exposure._head_or_get(
        "https://example.com/.env",
        ua="test",
        timeout=1,
    )

    assert status == 200
    assert sample == "APP_KEY=secret"
    assert methods == ["HEAD", "GET"]


def test_failed_source_sync_raises_after_retries(monkeypatch):
    monkeypatch.setattr(sync.db, "update_vulnerability_source", lambda *args, **kwargs: None)
    monkeypatch.setattr(sync.time, "sleep", lambda _delay: None)

    def fail(_path):
        raise ValueError("bad feed")

    with pytest.raises(RuntimeError, match="nvd sync failed"):
        sync._run_with_retries("nvd", fail, "missing.json")


def test_demo_seeding_does_not_overwrite_imported_cve(monkeypatch):
    cve_id = "CVE-2099-0001"
    db.upsert_cve(
        cve_id=cve_id,
        title="Authoritative title",
        description="Authoritative description",
        status="Analyzed",
        source_name="nvd",
        raw={"source": "live"},
    )
    monkeypatch.setattr(
        correlation,
        "_demo_entries",
        lambda: [
            {
                "cve": cve_id,
                "service": "ssh",
                "product": "openssh",
                "min": "1.0",
                "max": "9.9",
                "desc": "Synthetic demo description",
            }
        ],
    )

    assert correlation.seed_demo_cache() == 0

    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id,))
        row = cursor.fetchone()
        cursor.execute(
            "SELECT COUNT(*) AS n FROM cve_metrics WHERE cve_id=? AND source='bundled-demo'",
            (cve_id,),
        )
        demo_metrics = int(cursor.fetchone()["n"])
        cursor.execute("SELECT COUNT(*) AS n FROM cve_cpe_ranges WHERE cve_id=?", (cve_id,))
        demo_ranges = int(cursor.fetchone()["n"])

    assert row["title"] == "Authoritative title"
    assert row["source_name"] == "nvd"
    assert demo_metrics == 0
    assert demo_ranges == 0


def test_demo_seeding_tracks_its_own_source_without_touching_nvd(monkeypatch):
    cve_id = "CVE-2099-0003"
    db.update_vulnerability_source(
        "nvd",
        source_version="authoritative-feed",
        status="synced",
        record_count=123,
        success=True,
    )
    monkeypatch.setattr(
        correlation,
        "_demo_entries",
        lambda: [
            {
                "cve": cve_id,
                "service": "ssh",
                "product": "openssh",
                "min": "1.0",
                "max": "9.9",
                "desc": "Synthetic demo description",
            }
        ],
    )

    assert correlation.seed_demo_cache() == 1

    sources = {row["name"]: row for row in db.vulnerability_sources()}
    assert sources["nvd"]["source_version"] == "authoritative-feed"
    assert sources["nvd"]["record_count"] == 123
    assert sources["bundled-demo"]["status"] == "offline-cache-ready"
    assert sources["bundled-demo"]["record_count"] == 1


def test_udp_finding_identity_does_not_collide_with_tcp():
    tcp = correlation.finding_fingerprint(
        "example.com",
        53,
        "CVE-2099-0002",
        "cpe:2.3:a:example:dns:*:*:*:*:*:*:*:*",
    )
    udp = correlation.finding_fingerprint(
        "example.com",
        53,
        "CVE-2099-0002",
        "cpe:2.3:a:example:dns:*:*:*:*:*:*:*:*",
        proto="udp",
    )

    assert tcp != udp
    old_tcp_raw = (
        "scanner-vce|example.com|53|CVE-2099-0002|"
        "cpe:2.3:a:example:dns:*:*:*:*:*:*:*:*"
    )
    assert tcp == hashlib.sha256(old_tcp_raw.encode("utf-8")).hexdigest()
