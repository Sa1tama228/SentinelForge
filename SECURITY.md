# Security Policy

## Supported Versions

SentinelForge is currently pre-release. Security fixes are applied to the main branch.

## Reporting a Vulnerability

Please do not open a public issue for sensitive vulnerabilities.

Report privately with:

- affected version or commit
- reproduction steps
- impact
- suggested fix, if known

## Operational Safety

- Scan only authorized targets.
- Keep `block_public_targets` enabled unless you have a written scope.
- Treat honeypot logs and imported vulnerability data as sensitive.
- Avoid committing runtime DBs, exports, wordlists, and feed dumps.
