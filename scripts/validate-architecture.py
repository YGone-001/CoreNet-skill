#!/usr/bin/env python3
"""Validate the frozen five-layer architecture and Skill dependency direction.

Centralized layer order (this module is the authoritative definition):

    foundation = 0
    protocol = 1
    correlation = 2
    domain = 3
    orchestration = 4

Implementation is deliberately not a CoreNet Skill layer: implementation
source analysis is an external, optional activity performed only when a
user provides implementation evidence, never repository ownership.

Checks:
- every Skill directory under skills/<layer>/<skill>/ declares a manifest
  category equal to its parent layer;
- skill layer directories are exactly the authorized five; any other
  layer directory (for example a leftover implementation layer) fails;
- local Skill dependencies (required and optional) only point to the same
  layer or a lower layer; higher-layer dependencies fail;
- legitimate same-layer dependencies stay allowed, but dependency cycles
  among local Skills fail;
- dependency strings that do not resolve to a local CoreNet Skill (for
  example tshark) are external tools and are ignored for direction.

The dependency parser is deliberately not a package manager: it takes the
first kebab-case token of a dependency string (so "ngap >=0.1.0" resolves
to the local name "ngap") and treats everything else as external.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

LAYER_ORDER = ("foundation", "protocol", "correlation", "domain", "orchestration")
LAYER_RANK = {layer: rank for rank, layer in enumerate(LAYER_ORDER)}
SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
DEPENDENCY_NAME = re.compile(r"^\s*([a-z0-9][a-z0-9-]{0,63})")


def parse_dependency_name(dependency: str) -> str | None:
    """Return the leading kebab-case token of a dependency string.

    "ngap >=0.1.0" resolves to "ngap"; "tshark" stays "tshark". Anything
    without a leading token returns None. Version specifiers are ignored;
    this parser deliberately does not compare versions.
    """
    match = DEPENDENCY_NAME.match(dependency)
    return match.group(1) if match else None


def manifest_value(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def manifest_dependency_block(text: str, section: str) -> list[str]:
    """Read a required:/optional: list inside the dependencies: block.

    Limited to the repository's simple convention: a `dependencies:` key
    followed by indented `required:`/`optional:` keys, either as flow
    lists (`[a, b]`) or `- item` block lists. Flow-style empty lists
    (`[]`) yield no items.
    """
    dependencies = re.search(r"(?m)^dependencies:\s*$", text)
    if dependencies is None:
        return []
    items: list[str] = []
    in_section = False
    for line in text[dependencies.end():].splitlines():
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")):
            break
        stripped = line.strip()
        key_match = re.match(r"^([a-z_]+):\s*(\[([^\]]*)\])?\s*$", stripped)
        if key_match:
            key = key_match.group(1)
            if key == section:
                if key_match.group(2) is not None:
                    items.extend(item.strip() for item in key_match.group(3).split(",") if item.strip())
                    break
                in_section = True
                continue
            if in_section:
                break
            continue
        if in_section and stripped.startswith("- "):
            items.append(stripped[2:].strip())
    return items


def local_skill_registry(root: Path) -> dict[str, str]:
    """Map every local Skill name to its layer from the skills/ tree."""
    registry: dict[str, str] = {}
    skills_root = root / "skills"
    if not skills_root.is_dir():
        return registry
    for layer in LAYER_ORDER:
        layer_dir = skills_root / layer
        if not layer_dir.is_dir():
            continue
        for child in sorted(layer_dir.iterdir()):
            if child.is_dir() and SKILL_NAME.fullmatch(child.name):
                registry[child.name] = layer
    return registry


def read_manifest(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def check_skill_placement(root: Path, registry: dict[str, str], errors: list[str]) -> None:
    """Skill layer directories must be exactly the authorized five."""
    skills_root = root / "skills"
    for child in sorted(skills_root.iterdir()) if skills_root.is_dir() else []:
        if child.is_dir() and child.name not in LAYER_ORDER:
            errors.append(
                f"unauthorized skill layer directory: skills/{child.name}; "
                "implementation-specific Skills are not CoreNet ownership"
            )
    for layer in LAYER_ORDER:
        layer_dir = skills_root / layer
        if not layer_dir.is_dir():
            errors.append(f"missing skill layer directory: skills/{layer}")
            continue
        for child in sorted(layer_dir.iterdir()):
            if not child.is_dir():
                continue
            if not SKILL_NAME.fullmatch(child.name):
                errors.append(f"invalid Skill directory name: skills/{layer}/{child.name}")
                continue
            manifest = read_manifest(child / "manifest.yaml")
            if manifest is None:
                errors.append(f"missing manifest: skills/{layer}/{child.name}/manifest.yaml")
                continue
            category = manifest_value(manifest, "category")
            if category != layer:
                errors.append(
                    f"category/layer mismatch: skills/{layer}/{child.name} declares category '{category}' but must declare '{layer}'"
                )


def check_dependency_direction(
    skill_name: str,
    skill_layer: str,
    dependencies: list[str],
    registry: dict[str, str],
    errors: list[str],
) -> dict[str, str]:
    """Reject local dependencies on a higher layer; allow same/lower layer.

    Returns the resolved local edges so the caller can run cycle checks.
    """
    edges: dict[str, str] = {}
    for dependency in dependencies:
        name = parse_dependency_name(dependency)
        if name is None or name == skill_name:
            continue
        target_layer = registry.get(name)
        if target_layer is None:
            continue
        edges[name] = target_layer
        if LAYER_RANK[target_layer] > LAYER_RANK[skill_layer]:
            errors.append(
                f"dependency direction violation: {skill_name} ({skill_layer}) depends on {name} ({target_layer}); "
                "lower layers must never depend on higher layers"
            )
    return edges


def check_cycles(edges_by_skill: dict[str, dict[str, str]], errors: list[str]) -> None:
    """Deterministic depth-first cycle detection over local Skill edges."""
    state: dict[str, int] = {}

    def visit(node: str, trail: list[str]) -> None:
        state[node] = 1
        for target in sorted(edges_by_skill.get(node, {})):
            if state.get(target, 0) == 1:
                errors.append(f"dependency cycle detected: {' -> '.join(trail + [target])}")
            elif state.get(target, 0) == 0:
                visit(target, trail + [target])
        state[node] = 2

    for node in sorted(edges_by_skill):
        if state.get(node, 0) == 0:
            visit(node, [node])


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    skills_root = root / "skills"
    if not skills_root.is_dir():
        return [f"missing skills directory: {skills_root}"]
    registry = local_skill_registry(root)
    check_skill_placement(root, registry, errors)

    edges_by_skill: dict[str, dict[str, str]] = {}
    for skill_name, skill_layer in sorted(registry.items()):
        manifest = read_manifest(skills_root / skill_layer / skill_name / "manifest.yaml")
        if manifest is None:
            continue
        dependencies = manifest_dependency_block(manifest, "required") + manifest_dependency_block(manifest, "optional")
        edges = check_dependency_direction(skill_name, skill_layer, dependencies, registry, errors)
        if edges:
            edges_by_skill[skill_name] = edges
    check_cycles(edges_by_skill, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("architecture validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("architecture validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
