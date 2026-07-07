import json

from sentinelforge.core import db
from sentinelforge.modules.scanner.vuln import sync


def test_nvd_import_uses_payload_timestamp_for_source_freshness(tmp_path):
    nvd_path = tmp_path / "nvd.json"
    nvd_path.write_text(
        json.dumps(
            {
                "timestamp": "2000-01-02T03:00:01.1117682",
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2099-9201",
                            "vulnStatus": "Analyzed",
                            "published": "2099-01-01T00:00:00.000",
                            "lastModified": "2099-01-02T00:00:00.000",
                            "descriptions": [{"lang": "en", "value": "Synthetic NVD CVE."}],
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {
                                                    "vulnerable": True,
                                                    "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                                                    "versionStartIncluding": "1.0",
                                                    "versionEndExcluding": "2.0",
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    assert sync.import_nvd_json(nvd_path) == 1

    nvd_source = next(row for row in db.vulnerability_sources() if row["name"] == "nvd")
    assert nvd_source["source_version"] == "2000-01-02T03:00:01.1117682"

    freshness = next(row for row in db.vulnerability_source_freshness(max_age_hours=48) if row["name"] == "nvd")
    assert freshness["freshness_basis"] == "source_version"
    assert freshness["stale"]
