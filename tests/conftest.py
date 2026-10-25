"""Suite-wide isolation from the operator's real data root.

Several containment tests create and attach real APFS sparse images. Without this they
landed in ~/Library/Application Support/Quarry/runs, and an interrupted or parallel run
left them attached there. Every test now gets one throwaway QUARRY_HOME for the session,
set before any test module is imported, so nothing in the suite can read or write the
real database or run volumes.
"""
from __future__ import annotations

import os
import shutil
import tempfile

_HOME = tempfile.mkdtemp(prefix="quarry-test-home-")
os.environ["QUARRY_HOME"] = _HOME


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001
    shutil.rmtree(_HOME, ignore_errors=True)
