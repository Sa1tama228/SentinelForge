import os
import tempfile
from pathlib import Path


_TEST_DATA_DIR = Path(tempfile.mkdtemp(prefix="sentinelforge-tests-"))
os.environ.setdefault("SF_DATA_DIR", str(_TEST_DATA_DIR))
