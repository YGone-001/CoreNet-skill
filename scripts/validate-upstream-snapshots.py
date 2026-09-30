#!/usr/bin/env python3
"""Validate locally staged immutable third-party Skill snapshots."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


EXPECTED_COMMIT = "465ad05638fbe1d9e7f98671393396b6d9246393"
EXPECTED_SKILLS = (
    "wireshark-analysis",
    "protocol-reverse-engineering",
    "network-engineer",
    "systematic-debugging",
    "linux-troubleshooting",
    "c-pro",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate(root: Path) -> list[str]:
    """Return contract violations for the locally staged upstream snapshot."""
    errors: list[str] = []
    snapshot_root = root / "third_party" / "agentic-awesome-skills"
    upstream = snapshot_root / "UPSTREAM.md"
    license_file = snapshot_root / "LICENSE"
    manifest_file = snapshot_root / "MANIFEST.json"
    skills_root = snapshot_root / "skills"

    for path, label in ((upstream, "UPSTREAM.md"), (license_file, "LICENSE")):
        if not path.is_file():
            errors.append(f"missing required snapshot artifact: {label}")
    if not manifest_file.is_file():
        errors.append("missing required snapshot artifact: MANIFEST.json")
        return errors

    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return errors + [f"invalid MANIFEST.json: {exc}"]
    if not isinstance(manifest, dict):
        return errors + ["MANIFEST.json must contain an object"]
    if manifest.get("source_commit") != EXPECTED_COMMIT:
        errors.append("manifest source_commit does not match the pinned upstream commit")

    entries = manifest.get("skills")
    if not isinstance(entries, list):
        return errors + ["manifest skills must be a list"]
    names = [entry.get("name") for entry in entries if isinstance(entry, dict)]
    if len(entries) != len(names) or set(names) != set(EXPECTED_SKILLS) or len(names) != len(set(names)):
        errors.append("manifest must contain exactly the six authorized Skill roots")

    actual_roots = set()
    if skills_root.is_dir():
        actual_roots = {path.name for path in skills_root.iterdir() if path.is_dir()}
    else:
        errors.append("missing snapshot skills directory")
    if actual_roots != set(EXPECTED_SKILLS):
        errors.append("snapshot must contain exactly the six authorized Skill directories")

    third_party = root / "third_party"
    if third_party.exists():
        for path in third_party.rglob(".git"):
            errors.append(f"embedded Git metadata is not allowed: {path.relative_to(root)}")

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if name not in EXPECTED_SKILLS:
            continue
        if entry.get("source_path") != f"skills/{name}":
            errors.append(f"invalid source_path for {name}")
        if entry.get("snapshot_path") != f"third_party/agentic-awesome-skills/skills/{name}":
            errors.append(f"invalid snapshot_path for {name}")
        files = entry.get("files")
        if not isinstance(files, list):
            errors.append(f"manifest files must be a list for {name}")
            continue
        paths = [item.get("path") for item in files if isinstance(item, dict)]
        if len(files) != len(paths) or paths != sorted(paths) or len(paths) != len(set(paths)):
            errors.append(f"manifest file paths must be unique and sorted for {name}")
            continue
        skill_root = skills_root / name
        actual_files = sorted(
            path.relative_to(skill_root).as_posix()
            for path in skill_root.rglob("*")
            if path.is_file()
        ) if skill_root.is_dir() else []
        if actual_files != paths:
            errors.append(f"manifest file set does not match snapshot files for {name}")
        for item in files:
            if not isinstance(item, dict):
                continue
            relative = item.get("path")
            expected_hash = item.get("sha256")
            if not isinstance(relative, str) or not isinstance(expected_hash, str):
                errors.append(f"invalid file entry for {name}")
                continue
            candidate = skill_root / relative
            try:
                candidate.relative_to(skill_root)
            except ValueError:
                errors.append(f"manifest path escapes its Skill root for {name}: {relative}")
                continue
            if not candidate.is_file():
                errors.append(f"manifest file is missing: {name}/{relative}")
            elif sha256(candidate) != expected_hash:
                errors.append(f"SHA-256 mismatch: {name}/{relative}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("Upstream snapshot validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("Upstream snapshot validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
