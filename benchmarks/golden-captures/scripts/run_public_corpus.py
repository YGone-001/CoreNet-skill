#!/usr/bin/env python3
"""Execute the public 5GC golden capture corpus and generate differential benchmark records.

Coordinates:
1. Integrity preflight on external source captures.
2. Independent baseline verification and freezing.
3. Automated CoreNet Skill pipeline execution in an external working directory.
4. Differential comparison against independent human baselines.
5. Export of sanitized, non-sensitive benchmark results.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_DIR = ROOT / "benchmarks" / "golden-captures"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compare_results import compare_differential
from run_capture_pipeline import (
    ensure_tshark_path,
    get_skill_versions,
    get_tshark_version,
    run_pipeline,
)
from summarize_benchmark import generate_benchmark_summary

PUBLIC_CORPUS = [
    {
        "case_id": "public-5gc-baseline-lifecycle",
        "relative_path": "captures/baseline/full-lifecycle.pcap",
        "expected_sha256": "011d538635fe836c4ee50dcb011e3d46e53fd875baa7980c499829da912d2a97",
        "expected_size": 9512,
        "upstream_intent": "baseline full lifecycle registration session and release",
    },
    {
        "case_id": "public-5gc-baseline-user-plane",
        "relative_path": "captures/baseline/pdu-session-user-plane.pcap",
        "expected_sha256": "6040d3e54f79926d9ae2db70664fc1342d98716ab5c9ec00e147dae079ee81f7",
        "expected_size": 7645,
        "upstream_intent": "baseline pdu session user plane data exchange",
    },
    {
        "case_id": "public-5gc-registration-resync",
        "relative_path": "captures/baseline/registration-resynchronization.pcap",
        "expected_sha256": "65a30ad812db1f639bb1ca164b0e78908095ed8cf0a2e0535f5d1086fe41b901",
        "expected_size": 27760,
        "upstream_intent": "registration authentication synch failure and subsequent resynchronization recovery",
    },
    {
        "case_id": "public-5gc-auth-negative",
        "relative_path": "captures/fault-injection/authentication-key-mismatch/fault.pcap",
        "expected_sha256": "70cc13c537a745625fc59d974653f5b819874a8f1a74b14db416dc97a91801c7",
        "expected_size": 2300,
        "upstream_intent": "authentication key mismatch resulting in MAC failure and reject",
    },
    {
        "case_id": "public-5gc-auth-recovery",
        "relative_path": "captures/fault-injection/authentication-key-mismatch/recovery.pcap",
        "expected_sha256": "071add46ff3c429f88896e4ca9c1e45f2c107f6f1ff353118ff8fd06480dcb47",
        "expected_size": 4304,
        "upstream_intent": "authentication recovery with matching keys",
    },
    {
        "case_id": "public-5gc-access-plmn-negative",
        "relative_path": "captures/fault-injection/plmn-mismatch/fault.pcap",
        "expected_sha256": "6b2097195c4575865436f1d744621a30c1041846d8fb478b2727aca2767b051a",
        "expected_size": 1476,
        "upstream_intent": "plmn mismatch resulting in NGSetupFailure",
    },
    {
        "case_id": "public-5gc-access-plmn-recovery",
        "relative_path": "captures/fault-injection/plmn-mismatch/recovery.pcap",
        "expected_sha256": "5f97ad0fffa68908bee6c58e451cfc7e1aac8864d65e2d843cefce2bd85a2127",
        "expected_size": 1512,
        "upstream_intent": "plmn recovery resulting in NGSetupResponse",
    },
    {
        "case_id": "public-5gc-access-tai-negative",
        "relative_path": "captures/fault-injection/tac-mismatch/fault.pcap",
        "expected_sha256": "aace9deef78b6b575cdf55b26cedef64ce1bc7895684df870ab43c4596ae99de",
        "expected_size": 1476,
        "upstream_intent": "tac mismatch resulting in NGSetupFailure",
    },
    {
        "case_id": "public-5gc-access-tai-recovery",
        "relative_path": "captures/fault-injection/tac-mismatch/recovery.pcap",
        "expected_sha256": "4b6615b9741cac1b0a5ac7aa81b3ecf89ec6d1505df61c16ec3e2ca43eda733b",
        "expected_size": 1512,
        "upstream_intent": "tac recovery resulting in NGSetupResponse",
    },
    {
        "case_id": "public-5gc-dnn-negative",
        "relative_path": "captures/fault-injection/unsupported-dnn/fault.pcap",
        "expected_sha256": "fa8daf46694594f0ff007eca49a3ebe5e1ca54d14f6784e9000c11d6b77112a8",
        "expected_size": 4168,
        "upstream_intent": "unsupported dnn request resulting in session rejection without PFCP session",
    },
    {
        "case_id": "public-5gc-dnn-recovery",
        "relative_path": "captures/fault-injection/unsupported-dnn/recovery.pcap",
        "expected_sha256": "7156491cdc859a67c0f5ceff40e3a545cbb11d593e45b066011e14294431a8c4",
        "expected_size": 5556,
        "upstream_intent": "supported dnn session establishment recovery",
    },
    {
        "case_id": "public-5gc-external-path-negative",
        "relative_path": "captures/fault-injection/missing-n6-nat/fault.pcap",
        "expected_sha256": "87cb715ef940ce55adb1ab8bdc2c77b59efc040fcad4b4aa703c0747fb974c15",
        "expected_size": 2044,
        "upstream_intent": "missing n6 return route causing unanswered uplink icmp echo requests",
    },
    {
        "case_id": "public-5gc-external-path-recovery",
        "relative_path": "captures/fault-injection/missing-n6-nat/recovery.pcap",
        "expected_sha256": "aa93817d4d962e5af04b642f90053e96e14f2e3eb7531104c61cfee74160a84b",
        "expected_size": 4064,
        "upstream_intent": "n6 return route recovered with bidirectional icmp ping",
    },
]


def resolve_git_commit(repo_path: Path) -> str:
    try:
        proc = subprocess.run(["git", "-C", str(repo_path), "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        return proc.stdout.strip()
    except Exception:
        return "unknown"


def run_corpus(
    source_root: Path,
    work_root: Path,
    output_cases_dir: Path,
    import_to_repo: bool = False,
) -> None:
    ensure_tshark_path()
    tshark_ver = get_tshark_version()
    if "unavailable" in tshark_ver:
        raise RuntimeError("tshark is unavailable. Real capture benchmark execution is blocked.")

    source_commit = resolve_git_commit(source_root)
    corenet_commit = resolve_git_commit(ROOT)
    skill_versions = get_skill_versions()

    print(f"CoreNet Commit: {corenet_commit}")
    print(f"External Source: {source_root} (Commit: {source_commit})")
    print(f"TShark Version: {tshark_ver}")
    print(f"Work Root: {work_root}")
    print(f"Output Cases: {output_cases_dir}\n")

    work_root.mkdir(parents=True, exist_ok=True)
    output_cases_dir.mkdir(parents=True, exist_ok=True)

    for item in PUBLIC_CORPUS:
        case_id = item["case_id"]
        rel_path = item["relative_path"]
        expected_sha = item["expected_sha256"]
        intent = item["upstream_intent"]

        pcap_path = source_root / rel_path
        if not pcap_path.is_file():
            raise FileNotFoundError(f"Missing capture file: {pcap_path}")

        data = pcap_path.read_bytes()
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != expected_sha:
            raise ValueError(f"SHA-256 mismatch for {case_id}: expected {expected_sha}, got {actual_sha}")

        print(f"[{case_id}] Verified capture: {pcap_path.name} ({len(data)} bytes, sha256={actual_sha[:8]}...)")

        # Load independent human baseline
        baseline_file = BENCHMARK_DIR / "cases" / case_id / "human-baseline.json"
        if not baseline_file.is_file():
            raise FileNotFoundError(f"Missing independent human baseline: {baseline_file}")

        baseline_bytes = baseline_file.read_bytes()
        baseline_sha256 = hashlib.sha256(baseline_bytes).hexdigest()
        human_baseline = json.loads(baseline_bytes.decode("utf-8"))

        # Run automated pipeline in external work directory
        case_work_dir = work_root / case_id
        skill_summary = run_pipeline(pcap_path, case_work_dir, case_id, allow_repo_workdir=False)

        # Differential comparison
        differential = compare_differential(
            human_baseline,
            skill_summary,
            human_baseline_sha256=baseline_sha256,
            upstream_intent=intent,
        )

        # Save to output_cases_dir
        target_case_dir = output_cases_dir / case_id
        target_case_dir.mkdir(parents=True, exist_ok=True)

        # case.json
        case_json_source = BENCHMARK_DIR / "cases" / case_id / "case.json"
        if case_json_source.is_file() and case_json_source.resolve() != (target_case_dir / "case.json").resolve():
            shutil.copy2(case_json_source, target_case_dir / "case.json")

        if baseline_file.resolve() != (target_case_dir / "human-baseline.json").resolve():
            shutil.copy2(baseline_file, target_case_dir / "human-baseline.json")
        (target_case_dir / "skill-result-summary.json").write_text(
            json.dumps(skill_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (target_case_dir / "differential.json").write_text(
            json.dumps(differential, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        print(f"[{case_id}] Status: {differential['comparison_status']}, Layer: {differential['layer_attribution']}")

    # Generate benchmark summary
    summary_path = output_cases_dir.parent / "benchmark-summary.json" if output_cases_dir.name == "cases" else output_cases_dir / "benchmark-summary.json"
    generate_benchmark_summary(
        output_cases_dir,
        summary_path,
        corenet_commit=corenet_commit,
        external_source_commit=source_commit,
        tshark_version=tshark_ver,
        skill_versions=skill_versions,
    )
    print(f"\nBenchmark completed successfully! Summary written to: {summary_path}")

    if import_to_repo:
        repo_cases_dir = BENCHMARK_DIR / "cases"
        if output_cases_dir.resolve() != repo_cases_dir.resolve():
            print(f"Importing sanitized results to repository: {repo_cases_dir}")
            for case_dir in output_cases_dir.iterdir():
                if case_dir.is_dir():
                    dest_dir = repo_cases_dir / case_dir.name
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    for f in ("skill-result-summary.json", "differential.json"):
                        src_f = case_dir / f
                        if src_f.is_file():
                            shutil.copy2(src_f, dest_dir / f)
            repo_summary = BENCHMARK_DIR / "benchmark-summary.json"
            if summary_path.resolve() != repo_summary.resolve():
                shutil.copy2(summary_path, repo_summary)
            print("Import completed.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True, help="Path to external cloned capture repository")
    parser.add_argument("--work-root", type=Path, required=True, help="External work directory for pipeline artifacts")
    parser.add_argument("--output-root", type=Path, default=BENCHMARK_DIR / "cases", help="Directory where sanitized cases are written")
    parser.add_argument("--import-to-cases", action="store_true", help="Copy sanitized results to benchmarks/golden-captures/cases/")
    args = parser.parse_args(argv)

    try:
        run_corpus(args.source_root, args.work_root, args.output_root, args.import_to_cases)
        return 0
    except Exception as exc:
        print(f"Corpus run failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
