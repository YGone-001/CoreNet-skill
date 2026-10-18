"""Repository-level wiring for the 5GC authentication recovery regression suite.

Loads the package-local authentication recovery regression tests so they run
under repository-level test discovery and remote CI alongside the other
Domain Skill suites.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_TESTS = ROOT / "skills/domain/5gc-registration-mobility/tests/test_auth_recovery.py"

PACKAGE_SPEC = importlib.util.spec_from_file_location("registration_mobility_auth_recovery_tests", PACKAGE_TESTS)
PACKAGE_MODULE = importlib.util.module_from_spec(PACKAGE_SPEC)
assert PACKAGE_SPEC.loader is not None
PACKAGE_SPEC.loader.exec_module(PACKAGE_MODULE)
# The Domain package keeps its runtime self-contained under the conventional
# helper name ``procedure_model``.  Do not leak this package's temporary
# import into other packages or the generic-framework bridge loaded later in
# discovery.
sys.modules.pop("procedure_model", None)


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(PACKAGE_MODULE))
    return tests


if __name__ == "__main__":
    unittest.main()
