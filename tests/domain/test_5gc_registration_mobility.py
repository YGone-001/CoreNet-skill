"""Repository-level tests for the 5GC registration/mobility Domain Skill."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_TESTS = ROOT / "skills/domain/5gc-registration-mobility/tests/test_5gc_registration.py"
VALIDATOR_SCRIPT = ROOT / "scripts/validate-5gc-registration-mobility.py"

PACKAGE_SPEC = importlib.util.spec_from_file_location("registration_mobility_package_tests", PACKAGE_TESTS)
PACKAGE_MODULE = importlib.util.module_from_spec(PACKAGE_SPEC)
assert PACKAGE_SPEC.loader is not None
PACKAGE_SPEC.loader.exec_module(PACKAGE_MODULE)
# Both Domain packages deliberately keep their runtime self-contained and use
# the conventional helper name ``procedure_model``.  Do not leak this package's
# temporary import into the generic-framework bridge loaded later in discovery.
sys.modules.pop("procedure_model", None)

VALIDATOR_SPEC = importlib.util.spec_from_file_location("validate_5gc_registration_mobility", VALIDATOR_SCRIPT)
VALIDATOR = importlib.util.module_from_spec(VALIDATOR_SPEC)
assert VALIDATOR_SPEC.loader is not None
VALIDATOR_SPEC.loader.exec_module(VALIDATOR)


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(PACKAGE_MODULE))
    return tests


class RegistrationMobilityValidatorTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        destination = Path(temporary.name) / "repo"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        return temporary, destination

    def assert_error(self, root: Path, text: str) -> None:
        self.assertTrue(any(text in error for error in VALIDATOR.validate(root)))

    def test_committed_contract_passes(self):
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_protocol_ownership_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/domain/5gc-registration-mobility/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("protocols: []", "protocols:\n  - ngap"), encoding="utf-8")
            self.assert_error(root, "protocols must remain empty")

    def test_network_function_ownership_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/domain/5gc-registration-mobility/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("network_functions: []", "network_functions:\n  - amf"), encoding="utf-8")
            self.assert_error(root, "network_functions must remain empty")

    def test_implementation_source_mapping_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/domain/5gc-registration-mobility/scripts/procedure_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nOPEN5GS_SOURCE_HANDLER = 'amf/nas/handler.go'\n", encoding="utf-8")
            self.assert_error(root, "implementation or vendor source mapping")

    def test_subscriber_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/domain/5gc-registration-mobility/examples/inputs/full-registration/nas.jsonl"
            fixture.write_text(fixture.read_text(encoding="utf-8") + '{"supi": "001010000000001"}\n', encoding="utf-8")
            self.assert_error(root, "subscriber identifier value")

    def test_raw_decoder_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/domain/5gc-registration-mobility/scripts/procedure_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\ndef decode_ngap_payload(data):\n    return data\n", encoding="utf-8")
            self.assert_error(root, "raw protocol decoding code")

    def test_root_cause_schema_field_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema_path = root / "skills/domain/5gc-registration-mobility/schemas/5gc-registration-analysis.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["properties"]["root_cause"] = {"type": "string"}
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            self.assert_error(root, "causal or implementation fields")

    def test_missing_procedure_evidence_schema_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            (root / "skills/domain/5gc-registration-mobility/schemas/procedure-evidence.schema.json").unlink()
            self.assert_error(root, "missing required package file")

    def test_procedure_evidence_schema_divergence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema = root / "skills/domain/5gc-registration-mobility/schemas/procedure-evidence.schema.json"
            schema.write_text("{}\n", encoding="utf-8")
            self.assert_error(root, "procedure-evidence schema")

    def test_mandatory_authentication_chain_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model_path = root / "skills/domain/5gc-registration-mobility/rules/registration-model.json"
            model = json.loads(model_path.read_text(encoding="utf-8"))
            for stage in model["stages"]:
                if stage["stage_id"] == "authentication":
                    stage["conditional"] = False
            model_path.write_text(json.dumps(model), encoding="utf-8")
            self.assert_error(root, "authentication conditional")

    def test_repository_root_runtime_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            readme = root / "skills/domain/5gc-registration-mobility/README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\nRuntime path: ../../../shared\n", encoding="utf-8")
            self.assert_error(root, "repository-root runtime reference")


if __name__ == "__main__":
    unittest.main()
