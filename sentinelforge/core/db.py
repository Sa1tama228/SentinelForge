"""Compatibility facade for SentinelForge SQLite storage.

New code should prefer importing from sentinelforge.core.storage modules,
but the rest of the app can continue using `from sentinelforge.core import db`.
"""
from __future__ import annotations

from .storage.connection import *
from .storage.vulnerabilities import *
from .storage.assets import *
from .storage.scanner import *
from .storage.honeypot import *
from .storage.recon import *
