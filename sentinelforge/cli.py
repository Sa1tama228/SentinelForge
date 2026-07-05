"""Command-line interface for SentinelForge."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import db
from .modules.analysis import attack_paths
from .modules.recon import runner as recon_runner
from .modules.reports import exporter
from .modules.scanner import runner as scan_runner
from .modules.scanner.vuln import sync
from .modules import doctor, stress


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinelforge", description="Local security scanning, recon, and reporting toolkit.")
    parser.add_argument("--version", action="version", version=f"SentinelForge {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run a synchronous port scan")
    scan_p.add_argument("target")
    scan_p.add_argument("--ports", default="22,80,443")
    scan_p.add_argument("--profile", default="custom")
    scan_p.add_argument("--vulns", action="store_true")

    recon_p = sub.add_parser("recon", help="Run passive recon for a domain")
    recon_p.add_argument("domain")

    export_p = sub.add_parser("export", help="Export assets and findings")
    export_p.add_argument("--format", default="html", choices=exporter.FORMATS)
    export_p.add_argument("--out-dir", default="")

    paths_p = sub.add_parser("attack-paths", help="Rank likely entry points and attack paths")
    paths_p.add_argument("--limit", type=int, default=25)
    paths_p.add_argument("--no-low", action="store_true", help="Hide low-confidence exposure review items")

    graph_p = sub.add_parser("evidence-graph", help="Export correlated evidence graph as JSON")
    graph_p.add_argument("--summary-only", action="store_true")

    sub.add_parser("doctor", help="Check environment, optional tools, config, and DB health")

    stress_seed_p = sub.add_parser("stress-seed", help="Insert synthetic stress-test data")
    stress_seed_p.add_argument("--assets", type=int, default=200)
    stress_seed_p.add_argument("--findings-per-asset", type=int, default=3)
    stress_seed_p.add_argument("--honeypot-events", type=int, default=1000)
    stress_seed_p.add_argument("--recon-targets", type=int, default=50)

    stress_bench_p = sub.add_parser("stress-benchmark", help="Benchmark graph, attack paths, campaigns, and report export")
    stress_bench_p.add_argument("--report-format", default="json", choices=exporter.FORMATS)

    sub.add_parser("stress-clear", help="Remove synthetic stress-test data")

    sync_p = sub.add_parser("sync-vulns", help="Sync configured local vulnerability feeds")
    sync_p.add_argument("--validate-only", action="store_true")

    validate_p = sub.add_parser("validate-feed", help="Validate a vulnerability feed without importing it")
    validate_p.add_argument("kind", choices=["nvd_json", "cisa_kev", "epss_csv", "exploitdb_csv", "vendor_advisory_json"])
    validate_p.add_argument("path")

    cleanup_p = sub.add_parser("cleanup", help="Apply configured retention policy")
    cleanup_p.set_defaults(command="cleanup")

    args = parser.parse_args(argv)
    if args.command == "scan":
        run_id = db.create_scan_run(args.target, args.ports, check_vulns=args.vulns, profile_key=args.profile)
        scan_runner._execute(run_id, args.target, args.ports, check_vulns=args.vulns, profile_key=args.profile)
        row = db.connect().execute("SELECT status,error FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        print(json.dumps({"run_id": run_id, "status": row["status"], "error": row["error"]}, indent=2))
        return 0 if row["status"] == "done" else 2
    if args.command == "recon":
        target_id = recon_runner.run_all(args.domain)
        print(json.dumps({"target_id": target_id}, indent=2))
        return 0
    if args.command == "export":
        path = exporter.export_inventory(args.format, out_dir=args.out_dir or None)
        print(path)
        return 0
    if args.command == "attack-paths":
        print(json.dumps(attack_paths.analyze(limit=args.limit, include_low=not args.no_low), indent=2, ensure_ascii=False))
        return 0
    if args.command == "evidence-graph":
        payload = attack_paths.graph_payload()
        if args.summary_only:
            payload = payload["summary"]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0
    if args.command == "doctor":
        payload = doctor.run()
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0 if payload["ok"] else 2
    if args.command == "stress-seed":
        print(json.dumps(
            stress.seed(
                assets=args.assets,
                findings_per_asset=args.findings_per_asset,
                honeypot_events=args.honeypot_events,
                recon_targets=args.recon_targets,
            ),
            indent=2,
            ensure_ascii=False,
        ))
        return 0
    if args.command == "stress-benchmark":
        print(json.dumps(stress.benchmark(report_format=args.report_format), indent=2, ensure_ascii=False))
        return 0
    if args.command == "stress-clear":
        print(json.dumps(stress.clear(), indent=2, ensure_ascii=False))
        return 0
    if args.command == "sync-vulns":
        if args.validate_only:
            print(json.dumps(sync.validate_configured_sources(), indent=2, ensure_ascii=False))
        else:
            print(json.dumps(sync.sync_configured_sources(), indent=2, ensure_ascii=False))
        return 0
    if args.command == "validate-feed":
        print(json.dumps(sync.validate_import(args.kind, args.path), indent=2, ensure_ascii=False))
        return 0
    if args.command == "cleanup":
        print(json.dumps(db.apply_retention(), indent=2))
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
