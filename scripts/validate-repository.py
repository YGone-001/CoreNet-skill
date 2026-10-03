#!/usr/bin/env python3
"""Lightweight repository-contract validator; standard library only."""

from __future__ import annotations

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
    """docs/ARCHITECTURE.md must not describe an implemented Skill as a future candidate."""
    arch = root / "docs" / "ARCHITECTURE.md"
    if not arch.is_file():
        return
    implemented = implemented_skill_names(root)
    if not implemented:
        return
    for line in arch.read_text(encoding="utf-8").splitlines():
        if "candidate" not in line.lower():
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
    return errors


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
