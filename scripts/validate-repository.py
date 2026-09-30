#!/usr/bin/env python3
"""Lightweight repository-contract validator; standard library only."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DIRS = ("docs", "skills", "shared", "templates", "scripts", "tests")
REQUIRED_DOCS = ("ARCHITECTURE.md", "SKILL-SPEC.md", "TRACE-SCHEMA.md", "EVIDENCE-SCHEMA.md", "TESTING.md", "UPSTREAM.md", "NAMING.md", "ROADMAP.md")
REQUIRED_SCHEMAS = ("skill-manifest.schema.json", "trace-event.schema.json", "evidence.schema.json", "diagnostic-result.schema.json")
TEMPLATE_FILES = ("SKILL.md", "README.md", "manifest.yaml", "references/README.md", "rules/README.md", "scripts/README.md", "filters/README.md", "examples/README.md", "tests/README.md")
SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
GENERATED = ("__pycache__", ".pyc", "node_modules", ".DS_Store", "Thumbs.db")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def main() -> int:
    errors: list[str] = []
    for directory in REQUIRED_DIRS:
        if not (ROOT / directory).is_dir():
            fail(errors, f"missing required directory: {directory}")
    for document in REQUIRED_DOCS:
        if not (ROOT / "docs" / document).is_file():
            fail(errors, f"missing required document: docs/{document}")
    for schema in REQUIRED_SCHEMAS:
        path = ROOT / "shared" / "schemas" / schema
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(errors, f"invalid schema {path.relative_to(ROOT)}: {exc}")
    template = ROOT / "templates" / "skill-template"
    for relative in TEMPLATE_FILES:
        if not (template / relative).is_file():
            fail(errors, f"missing template file: templates/skill-template/{relative}")
    for layer in ("foundation", "protocol", "domain", "implementation", "orchestration"):
        if not (ROOT / "skills" / layer).is_dir():
            fail(errors, f"missing skill layer: skills/{layer}")
    for path in (ROOT / "skills").rglob("*"):
        if path.is_dir() and path.parent.name in {"skills", "foundation", "protocol", "domain", "implementation", "orchestration"} and path.name not in {"foundation", "protocol", "domain", "implementation", "orchestration"}:
            if not SKILL_NAME.fullmatch(path.name):
                fail(errors, f"invalid Skill directory name: {path.relative_to(ROOT)}")
            for required in ("SKILL.md", "README.md", "manifest.yaml"):
                if not (path / required).is_file():
                    fail(errors, f"incomplete Skill: {path.relative_to(ROOT)}/{required} is missing")
    try:
        tracked = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines()
    except (OSError, subprocess.CalledProcessError):
        tracked = []
    for name in tracked:
        if any(part in name for part in GENERATED):
            fail(errors, f"forbidden generated file tracked: {name}")
    if errors:
        print("Repository validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("Repository validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
