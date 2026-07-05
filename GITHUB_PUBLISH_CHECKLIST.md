# GitHub Publish Checklist

Before pushing this directory as a repository:

- Run `python -m pip install -e ".[dev]"` in a fresh virtual environment.
- Run `python -m pytest -q`.
- Run `python -m ruff check .`.
- Run `python -m sentinelforge.cli doctor`.
- Confirm `data/config.json`, database files, feed dumps, wordlists, exports, and local tool checkouts are not committed.
- If using Nikto, install it separately or place it under `tools/nikto/`; that directory is intentionally ignored.
- Keep PyShark/Wireshark/TShark documented as WIP until packet-capture workflows are implemented.

This prepared copy intentionally includes `data/config.example.json` only. Runtime config is created locally by the app.
