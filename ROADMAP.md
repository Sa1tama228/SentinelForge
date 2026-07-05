# SentinelForge Engineering Roadmap

This backlog focuses on making SentinelForge more than a basic scanner while keeping false positives and unsafe defaults under control.

## Evidence Graph

- Done: add in-memory graph layer for assets, services, findings, vulnerabilities, recon observations, control gaps, honeypot signals, and web-audit signals.
- Done: expose evidence graph through CLI and asset drilldown.
- Done: suppress CVE-backed paths when distribution advisory evidence says the local package is patched.
- Persist optional graph snapshots for reports and scan comparisons.
- Add graph edges for leaked secret indicators, exposed config files, package inventory, vendor advisory state, and identity surfaces.
- Add contradictory-evidence handling, for example vulnerable banner plus distro advisory fixed.
- Add path templates for:
  - exposed `.env` -> credential leak -> database/admin surface
  - web admin panel -> weak control gap -> CVE-backed service
  - package inventory -> fixed/not-affected advisory -> suppress banner-only CVE path
  - honeypot campaign -> matching exposed service -> hardening priority
- Add graph diffing between scans.

## Scanner

- Done: optional Nikto integration as an external web-audit engine, disabled by default.
- Done: protocol metadata extraction for HTTP, SSH, FTP, SMTP, MySQL/MariaDB, Redis, and PostgreSQL signals.
- Add protocol-specific fingerprints for HTTP, TLS, SSH, FTP, SMTP, MySQL/MariaDB, PostgreSQL, Redis, and SMB metadata.
- Add per-fingerprint confidence explanations.
- Add safe web exposure checks as a separate profile from port scanning.
- Add cancellation and progress reporting for external engines.

## Vulnerability Intelligence

- Done: add initial source-quality scoring for vulnerability feeds.
- Add source-quality scoring per feed.
- Add ecosystem-aware advisory parsing for Debian, Ubuntu, Red Hat, Alpine, Python, npm, Maven, Go, and containers.
- Add affected/fixed/not-affected advisory state into vulnerability matching.
- Improve duplicate merge logic across NVD, CISA KEV, EPSS, Exploit-DB, vendor, and distribution feeds.
- Add feed schema presets and sample validation output in the UI.

## Recon

- Done: add recon source quality scoring in the Recon view.
- Add source reliability scoring.
- Add certificate transparency diffing.
- Add stronger subdomain takeover confidence gates.
- Correlate recon exposure findings directly into graph path templates.
- Add DNS and technology timeline views.

## Honeypot

- Done: add campaign clustering by source IP, service mix, classification, paths, alerts, and credential indicators.
- Cluster sessions into campaigns by source, user-agent, path sequence, timing, and payload similarity.
- Add attacker intent scoring.
- Normalize payloads and extract more structured indicators.
- Feed campaign pressure into graph scoring without turning it into vulnerability proof.
- Add export summaries focused on signal, not raw event volume.

## UI and Reports

- Done: add asset drilldown graph-neighbor context.
- Done: add executive summary, evidence graph coverage, and top attack paths to Markdown/HTML reports.
- Add asset drilldown showing graph neighbors and top path reasons.
- Add attack-path details with expandable evidence edges.
- Add report sections for executive summary, top attack paths, changed since last scan, and validation notes.
- Add confidence/severity vocabulary consistency across all modules.

## Packaging

- Add sample config and sample data.
- Add screenshots and demo workflow.
- Add release checklist for public GitHub publishing.
- Document optional external tools and their permissions clearly.
