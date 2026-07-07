from sentinelforge.modules.scanner import fingerprint, protocols, runner
from sentinelforge.modules.scanner.service_ports import looks_like_https_port


HTTPS_9443_BANNER = (
    "HTTP/1.1 200 OK\n"
    "Server: nginx/1.24.0\n"
    "Strict-Transport-Security: max-age=31536000\n"
    "\n"
    "TLS cert subject=CN=app.local issuer=CN=test san=app.local "
    "tls_version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 alpn=http/1.1\n"
    "[scan] latency_ms=12"
)


def test_fingerprint_identifies_tls_http_on_non_standard_port():
    service, version = fingerprint.identify(9443, HTTPS_9443_BANNER)

    assert service == "https"
    assert version == "nginx 1.24.0"


def test_fingerprint_treats_nmap_product_banner_on_9443_as_https():
    service, version = fingerprint.identify(9443, "nginx 1.24.0")

    assert service == "https"
    assert version == "nginx 1.24.0"


def test_non_standard_tls_http_gets_http_metadata_and_nikto_eligibility():
    metadata = protocols.extract_metadata(9443, "https", HTTPS_9443_BANNER)

    assert metadata["protocol"] == "http"
    assert metadata["server"] == "nginx/1.24.0"
    assert runner._is_web_service(9443, "https")


def test_ports_ending_in_443_are_tls_probe_candidates():
    assert looks_like_https_port(9443)
    assert looks_like_https_port(10443)
