import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinelforge import cli


def test_cli_validate_feed_outputs_json(tmp_path, capsys):
    path = tmp_path / "epss.csv"
    path.write_text("cve,epss,percentile\nCVE-2099-90001,0.42,0.9\n", encoding="utf-8")
    assert cli.main(["validate-feed", "epss_csv", str(path)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"]
    assert data["importable_rows"] == 1


def test_cli_cleanup_outputs_json(capsys):
    assert cli.main(["cleanup"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "honeypot_events" in data
