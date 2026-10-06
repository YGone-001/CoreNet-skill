#!/usr/bin/env python3
"""Lightweight repository-contract validator; standard library only."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Authoritative five-layer order; keep in sync with scripts/validate-architecture.py,
# whose consistency with this tuple is asserted in tests/structure.
# Implementation is not a CoreNet Skill layer: implementation source analysis
# is an external activity, never repository ownership.
LAYERS = ("foundation", "protocol", "correlation", "domain", "orchestration")
REQUIRED_DIRS = ("docs", "skills", "shared", "templates", "scripts", "tests")
REQUIRED_DOCS = ("ARCHITECTURE.md", "SKILL-SPEC.md", "TRACE-SCHEMA.md", "EVIDENCE-SCHEMA.md", "TESTING.md", "UPSTREAM.md", "NAMING.md", "ROADMAP.md")
REQUIRED_SCHEMAS = ("skill-manifest.schema.json", "trace-event.schema.json", "evidence.schema.json", "diagnostic-result.schema.json")
TEMPLATE_FILES = ("SKILL.md", "README.md", "manifest.yaml", "references/README.md", "rules/README.md", "scripts/README.md", "filters/README.md", "examples/README.md", "tests/README.md")
SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
GENERATED = ("__pycache__", ".pyc", "node_modules", ".DS_Store", "Thumbs.db")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def implemented_skill_names(root: Path) -> set[str]:
    """Derive the implemented Skill catalog from actual Skill directories."""
    names: set[str] = set()
    for layer in LAYERS:
        layer_dir = root / "skills" / layer
        if layer_dir.is_dir():
            for child in layer_dir.iterdir():
                if child.is_dir() and (child / "manifest.yaml").is_file():
                    names.add(child.name)
    return names


def check_architecture_catalog(root: Path, errors: list[str]) -> None:
    """docs/ARCHITECTURE.md must not describe an implemented Skill as a future candidate.

    Only lines phrased as the future catalog ("candidates remain ...",
    "candidates include ...") are checked, so implementation descriptions that
    merely mention the word candidate are not flagged.
    """
    arch = root / "docs" / "ARCHITECTURE.md"
    if not arch.is_file():
        return
    implemented = implemented_skill_names(root)
    if not implemented:
        return
    future_catalog = re.compile(r"(?i)candidates?\s+(?:remain|include)")
    for line in arch.read_text(encoding="utf-8").splitlines():
        if not future_catalog.search(line):
            continue
        for name in sorted(implemented):
            if re.search(rf"`{re.escape(name)}`", line):
                fail(errors, f"docs/ARCHITECTURE.md lists implemented Skill `{name}` as a future candidate")


def validate(root: Path) -> list[str]:
    """Validate repository layout against the contract; returns error list."""
    errors: list[str] = []
    for directory in REQUIRED_DIRS:
        if not (root / directory).is_dir():
            fail(errors, f"missing required directory: {directory}")
    for document in REQUIRED_DOCS:
        if not (root / "docs" / document).is_file():
            fail(errors, f"missing required document: docs/{document}")
    for schema in REQUIRED_SCHEMAS:
        path = root / "shared" / "schemas" / schema
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(errors, f"invalid schema {path.relative_to(root)}: {exc}")
    template = root / "templates" / "skill-template"
    for relative in TEMPLATE_FILES:
        if not (template / relative).is_file():
            fail(errors, f"missing template file: templates/skill-template/{relative}")
    for layer in LAYERS:
        if not (root / "skills" / layer).is_dir():
            fail(errors, f"missing skill layer: skills/{layer}")
    for path in (root / "skills").rglob("*"):
        if path.is_dir() and path.parent.name in {"skills", *LAYERS} and path.name not in set(LAYERS):
            if not SKILL_NAME.fullmatch(path.name):
                fail(errors, f"invalid Skill directory name: {path.relative_to(root)}")
            for required in ("SKILL.md", "README.md", "manifest.yaml"):
                if not (path / required).is_file():
                    fail(errors, f"incomplete Skill: {path.relative_to(root)}/{required} is missing")
    check_architecture_catalog(root, errors)
    try:
        tracked = subprocess.check_output(["git", "ls-files"], cwd=root, text=True).splitlines()
    except (OSError, subprocess.CalledProcessError):
        tracked = []
    for name in tracked:
        if any(part in name for part in GENERATED):
            fail(errors, f"forbidden generated file tracked: {name}")
    check_implementation_neutral_vocabulary(root, tracked, errors)
    return errors


def check_implementation_neutral_vocabulary(root: Path, tracked: list[str], errors: list[str]) -> None:
    """Durable governance gate: the tracked tree stays implementation-neutral.

    CoreNet Skill is a standards-based repository. Repository-owned telecom
    knowledge derives from 3GPP specifications, directly applicable protocol
    standards, reviewed dissector contracts, and observable evidence. Named
    implementation-project expertise must never become Skill ownership, and
    project-specific source/log/config mappings are prohibited.

    The prohibited implementation-project tokens are not stored literally in
    any tracked file — including this validator. They are defined once in
    ``scripts/implementation_policy.py`` via code-point construction, and
    detection compares SHA-256 digests of case-folded complete tokens from
    every tracked text file against the policy digest set, so any
    capitalization of any prohibited token is rejected without the policy
    itself violating its own rule.
    """
    policy_path = Path(__file__).resolve().parent / "implementation_policy.py"
    policy_spec = importlib.util.spec_from_file_location("implementation_policy", policy_path)
    policy = importlib.util.module_from_spec(policy_spec)
    assert policy_spec.loader is not None
    policy_spec.loader.exec_module(policy)

    text_suffixes = {".md", ".py", ".yaml", ".yml", ".json", ".jsonl", ".txt", ".cfg", ".toml", ".html", ".csv"}
    for name in tracked:
        path = root / name
        suffix = path.suffix.lower()
        if suffix not in text_suffixes and suffix != "":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # Tracked path names participate in the gate too.
        found = policy.find_prohibited_tokens(name) + policy.find_prohibited_tokens(text)
        if found:
            fail(errors,
                 "implementation-project token is prohibited in tracked content "
                 f"(case-insensitive complete-token policy): {name}")


def main() -> int:
    errors = validate(ROOT)
    if errors:
        print("Repository validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("Repository validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
