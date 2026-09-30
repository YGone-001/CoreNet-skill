#!/usr/bin/env python3
"""Validate CoreNet Foundation Skill contracts and embedded snapshots."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


PINNED_COMMIT = "465ad05638fbe1d9e7f98671393396b6d9246393"
SKILLS = ("wireshark-analysis", "protocol-reverse-engineering", "network-engineer", "systematic-debugging", "linux-troubleshooting", "c-pro")
REQUIRED = ("SKILL.md", "README.md", "manifest.yaml", "UPSTREAM.md", "upstream-manifest.json")
SECTIONS = ("Purpose", "Scope", "Non-Goals", "Inputs", "Outputs", "Dependencies", "Workflow", "Evidence Rules", "Failure Handling", "Validation", "References")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def manifest_value(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+)$", text)
    return match.group(1).strip() if match else None


def validate_embedded(skill: Path, staged: Path | None = None) -> list[str]:
    errors: list[str] = []
    name = skill.name
    for required in REQUIRED:
        if not (skill / required).is_file():
            errors.append(f"{name}: missing {required}")
    if not (skill / "upstream").is_dir():
        return errors + [f"{name}: missing upstream directory"]
    if any(path.name == ".git" for path in (skill / "upstream").rglob(".git")):
        errors.append(f"{name}: embedded Git metadata is not allowed")
    if (skill / "SKILL.md").is_file():
        text = (skill / "SKILL.md").read_text(encoding="utf-8")
        for section in SECTIONS:
            if f"## {section}" not in text:
                errors.append(f"{name}: SKILL.md is missing {section}")
    for wrapper in ("SKILL.md", "README.md", "manifest.yaml"):
        path = skill / wrapper
        if path.is_file():
            wrapper_text = path.read_text(encoding="utf-8")
            if "third_party/" in wrapper_text:
                errors.append(f"{name}: {wrapper} has a runtime third_party reference")
            if "../" in wrapper_text:
                errors.append(f"{name}: {wrapper} has a path escaping the standalone package")
    if not (skill / "manifest.yaml").is_file() or not (skill / "upstream-manifest.json").is_file():
        return errors
    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    for key, expected in (("name", name), ("version", "0.1.0"), ("category", "foundation")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"{name}: manifest {key} is not {expected}")
    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append(f"{name}: manifest has mandatory dependencies")
    for key in ("protocols", "interfaces", "network_functions"):
        if manifest_value(manifest, key) != "[]":
            errors.append(f"{name}: manifest {key} must be empty")
    if not re.search(rf"(?m)^\s+commit:\s*{PINNED_COMMIT}\s*$", manifest):
        errors.append(f"{name}: manifest pinned commit is incorrect")
    try:
        embedded = json.loads((skill / "upstream-manifest.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return errors + [f"{name}: invalid upstream-manifest.json: {exc}"]
    if embedded.get("source_commit") != PINNED_COMMIT or embedded.get("source_path") != f"skills/{name}":
        errors.append(f"{name}: upstream manifest source identity is incorrect")
    files = embedded.get("files")
    if not isinstance(files, list):
        return errors + [f"{name}: upstream manifest files is invalid"]
    listed = [item.get("path") for item in files if isinstance(item, dict)]
    actual = sorted(path.relative_to(skill / "upstream").as_posix() for path in (skill / "upstream").rglob("*") if path.is_file())
    if listed != actual:
        errors.append(f"{name}: upstream manifest file set does not match embedded snapshot")
    for item in files:
        relative = item.get("path") if isinstance(item, dict) else None
        expected = item.get("sha256") if isinstance(item, dict) else None
        target = skill / "upstream" / str(relative)
        if not isinstance(relative, str) or not isinstance(expected, str) or not target.is_file():
            errors.append(f"{name}: invalid or missing embedded file entry")
        elif digest(target) != expected:
            errors.append(f"{name}: embedded SHA-256 mismatch for {relative}")
    if staged is not None:
        staged_files = sorted(path.relative_to(staged).as_posix() for path in staged.rglob("*") if path.is_file()) if staged.is_dir() else []
        if actual != staged_files:
            errors.append(f"{name}: staged and embedded file sets differ")
        for relative in actual:
            if (staged / relative).is_file() and digest(skill / "upstream" / relative) != digest(staged / relative):
                errors.append(f"{name}: staged and embedded bytes differ for {relative}")
    return errors


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    foundation = root / "skills" / "foundation"
    actual = {path.name for path in foundation.iterdir() if path.is_dir()} if foundation.is_dir() else set()
    if actual != set(SKILLS):
        errors.append("Foundation directory must contain exactly the six authorized Skills")
    for name in SKILLS:
        errors.extend(validate_embedded(foundation / name, root / "third_party" / "agentic-awesome-skills" / "skills" / name))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("Foundation Skill validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("Foundation Skill validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
