"""Repository-level wiring for the recovered-outcome orchestration regression suite.

Loads the package-local recovered-outcome classification regression tests so
they run under repository-level test discovery and remote CI alongside the
other Failure Boundary Orchestration suites.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_TESTS = ROOT / "skills/orchestration/5gc-failure-boundary/tests/test_recovered_outcome.py"

PACKAGE_SPEC = importlib.util.spec_from_file_location("failure_boundary_recovered_outcome_tests", PACKAGE_TESTS)
PACKAGE_MODULE = importlib.util.module_from_spec(PACKAGE_SPEC)
assert PACKAGE_SPEC.loader is not None
PACKAGE_SPEC.loader.exec_module(PACKAGE_MODULE)
# The Orchestration package keeps its runtime self-contained under the
# conventional helper name ``failure_boundary_model``.  Do not leak this
# package's temporary import into other packages loaded later in discovery.
sys.modules.pop("failure_boundary_model", None)


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(PACKAGE_MODULE))
    return tests


if __name__ == "__main__":
    unittest.main()
