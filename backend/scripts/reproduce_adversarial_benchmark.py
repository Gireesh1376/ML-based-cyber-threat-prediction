#!/usr/bin/env python3
"""
Reproduce Adversarial Benchmark Script.

Loads existing baseline and hardened model artifacts and the held-out test split,
computes the empirical adversarial robustness benchmark via compute_adversarial_benchmark(),
compares the reproduced metrics with the reference saved in backend/models/adversarial_metrics.json,
and writes the reproduced output to the specified path.

Usage:
    python backend/scripts/reproduce_adversarial_benchmark.py --output backend/models/adversarial_metrics_reproduced.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Determine repo root and backend directory relative to this script
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
REPO_ROOT = BACKEND_DIR.parent

# Ensure backend directory is in sys.path for application imports
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def resolve_repo_path(path_str: str | Path) -> Path:
    """Resolves a path relative to the repository root if not already absolute."""
    p = Path(path_str)
    if p.is_absolute():
        return p.resolve()
    return (REPO_ROOT / p).resolve()


def compare_metrics(
    reproduced: Any,
    reference: Any,
    path: str = "",
    tolerance: float = 1e-4,
) -> list[str]:
    """Recursively compares reproduced metrics against reference metrics.

    Floats are compared within the given tolerance. Returns a list of human-readable
    mismatch descriptions.
    """
    mismatches: list[str] = []

    if type(reproduced) != type(reference):
        # Allow int and float comparisons
        if isinstance(reproduced, (int, float)) and isinstance(reference, (int, float)):
            pass
        else:
            mismatches.append(
                f"{path}: Type mismatch (reproduced={type(reproduced).__name__}, reference={type(reference).__name__})"
            )
            return mismatches

    if isinstance(reference, dict):
        ref_keys = set(reference.keys())
        rep_keys = set(reproduced.keys())

        missing = ref_keys - rep_keys
        if missing:
            mismatches.append(f"{path}: Missing keys in reproduced metrics: {sorted(missing)}")

        extra = rep_keys - ref_keys
        if extra:
            mismatches.append(f"{path}: Unexpected extra keys in reproduced metrics: {sorted(extra)}")

        for key in sorted(ref_keys.intersection(rep_keys)):
            subpath = f"{path}.{key}" if path else key
            mismatches.extend(
                compare_metrics(
                    reproduced[key],
                    reference[key],
                    path=subpath,
                    tolerance=tolerance,
                )
            )

    elif isinstance(reference, list):
        if len(reproduced) != len(reference):
            mismatches.append(
                f"{path}: List length mismatch (reproduced={len(reproduced)}, reference={len(reference)})"
            )
        else:
            for i, (rep_item, ref_item) in enumerate(zip(reproduced, reference)):
                subpath = f"{path}[{i}]"
                mismatches.extend(
                    compare_metrics(
                        rep_item,
                        ref_item,
                        path=subpath,
                        tolerance=tolerance,
                    )
                )

    elif isinstance(reference, (int, float)):
        diff = abs(float(reproduced) - float(reference))
        if diff > tolerance:
            mismatches.append(
                f"{path}: Value mismatch (reproduced={reproduced}, reference={reference}, diff={diff:.6f} > tol={tolerance})"
            )

    else:
        if reproduced != reference:
            mismatches.append(
                f"{path}: Value mismatch (reproduced={reproduced!r}, reference={reference!r})"
            )

    return mismatches


def format_summary_table(reproduced: dict[str, Any]) -> str:
    """Formats a concise human-readable summary of key benchmark metrics."""
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append(f"{'ADVERSARIAL ROBUSTNESS BENCHMARK SUMMARY':^78}")
    lines.append("=" * 78)

    # Clean metrics
    clean = reproduced.get("clean_metrics", {})
    lines.append("Clean Performance Metrics:")
    lines.append(f"  - Baseline Clean Accuracy : {clean.get('baseline_accuracy', 'N/A')}")
    lines.append(f"  - Hardened Clean Accuracy : {clean.get('hardened_accuracy', 'N/A')}")
    lines.append(f"  - Baseline Attack Recall  : {clean.get('baseline_attack_recall', 'N/A')}")
    lines.append(f"  - Hardened Attack Recall  : {clean.get('hardened_attack_recall', 'N/A')}")
    lines.append(f"  - Baseline F1-Score       : {clean.get('baseline_f1', 'N/A')}")
    lines.append(f"  - Hardened F1-Score       : {clean.get('hardened_f1', 'N/A')}")
    lines.append(f"  - Clean FPR (Base/Hard)   : {clean.get('baseline_fpr', 'N/A')} / {clean.get('hardened_fpr', 'N/A')}")
    lines.append(f"  - FPR Penalty             : {clean.get('fpr_penalty', 'N/A')}")
    lines.append("-" * 78)

    # Adversarial summaries at eps=0.20
    lines.append("Adversarial Evasion Mitigations (epsilon = 0.20):")
    for key, name in [
        ("adversarial_summary", "DEMGAN Manifold Drift"),
        ("fgsm_summary", "Constrained FGSM (White-Box)"),
        ("uap_summary", "Universal Perturbation (UAP)"),
    ]:
        summary = reproduced.get(key, {})
        base_ev = summary.get("baseline_evasion_rate", "N/A")
        hard_ev = summary.get("hardened_evasion_rate", "N/A")
        red_pct = summary.get("evasion_reduction_pct", "N/A")
        adapt_ev = summary.get("adaptive_hardened_evasion_rate", "N/A")
        lines.append(
            f"  * {name:<32}: Base Evasion={base_ev} -> Hardened={hard_ev} "
            f"(Reduction: {red_pct}%, Adaptive: {adapt_ev})"
        )
    lines.append("-" * 78)

    # Sweep overview
    sweep = reproduced.get("sweep", [])
    lines.append(f"Perturbation Sweep Evaluations: {len(sweep)} configurations (3 methods x 3 budgets)")
    all_valid = all(s.get("constraint_validity_pct") == 100.0 for s in sweep)
    lines.append(f"Network Flow Constraint Validity: {'100% across all evaluated samples' if all_valid else 'Violations detected!'}")
    lines.append("=" * 78)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reproduce and verify adversarial benchmark robustness metrics.",
        epilog=(
            "Example:\n"
            "  python backend/scripts/reproduce_adversarial_benchmark.py "
            "--output backend/models/adversarial_metrics_reproduced.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Path to write the reproduced benchmark metrics JSON (relative to repository root or absolute).",
    )
    parser.add_argument(
        "--reference",
        "-r",
        type=str,
        default="backend/models/adversarial_metrics.json",
        help="Path to reference benchmark metrics JSON for comparison (default: backend/models/adversarial_metrics.json).",
    )
    parser.add_argument(
        "--tolerance",
        "-t",
        type=float,
        default=1e-4,
        help="Numerical tolerance for comparing float metrics (default: 0.0001).",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress detailed progress messages and summary tables.",
    )

    args = parser.parse_args()

    # Import backend application modules
    try:
        from app.config import MODELS_DIR, RAW_DIR
        from app.ml import load_artifacts, model_path
        from app.ml.adversarial import (
            HARDENED_MODEL_PATH,
            compute_adversarial_benchmark,
        )
        from app.ml.features import load_nsl_kdd, split_zero_day
    except ImportError as e:
        print(f"[ERROR] Failed to import backend modules: {e}", file=sys.stderr)
        print(f"Ensure backend directory is located at: {BACKEND_DIR}", file=sys.stderr)
        return 1

    # 1. Verify existence of required model artifacts (no retraining allowed)
    base_model_file = model_path()
    if not base_model_file.exists():
        print(
            f"[ERROR] Baseline model artifact not found at: {base_model_file}. "
            "Retraining is strictly disallowed during reproduction.",
            file=sys.stderr,
        )
        return 1

    if not HARDENED_MODEL_PATH.exists():
        print(
            f"[ERROR] Hardened model artifact not found at: {HARDENED_MODEL_PATH}. "
            "Retraining is strictly disallowed during reproduction.",
            file=sys.stderr,
        )
        return 1

    # 2. Verify existence of reference metrics
    ref_path = resolve_repo_path(args.reference)
    if not ref_path.exists():
        print(f"[ERROR] Reference metrics file not found at: {ref_path}", file=sys.stderr)
        return 1

    # 3. Verify existence of test dataset
    test_data_path = RAW_DIR / "KDDTest+.txt"
    if not test_data_path.exists():
        print(f"[ERROR] Held-out test dataset not found at: {test_data_path}", file=sys.stderr)
        return 1

    if not args.quiet:
        print("[INFO] Loading baseline and hardened model artifacts...")

    # Load artifacts without triggering retraining or modification
    base_artifacts, _ = load_artifacts(base_model_file)
    base_artifacts.is_hardened = False

    hardened_artifacts, _ = load_artifacts(HARDENED_MODEL_PATH)
    hardened_artifacts.is_hardened = True

    if not args.quiet:
        print(f"[INFO] Loading held-out test split from {test_data_path}...")

    # Load the held-out test split
    test_df = load_nsl_kdd(test_data_path)
    known_test, _ = split_zero_day(test_df)

    if not args.quiet:
        print(f"[INFO] Executing compute_adversarial_benchmark() on {len(known_test)} test flows...")

    # Compute reproduced adversarial benchmark
    reproduced_metrics = compute_adversarial_benchmark(
        base_artifacts=base_artifacts,
        hardened_artifacts=hardened_artifacts,
        test_df=known_test,
    )

    # 4. Write reproduced metrics if --output was provided
    if args.output:
        output_path = resolve_repo_path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(reproduced_metrics, indent=2), encoding="utf-8")
        if not args.quiet:
            print(f"[INFO] Reproduced benchmark metrics written to: {output_path}")

    # 5. Load reference metrics and perform rigorous comparison
    if not args.quiet:
        print(f"[INFO] Comparing reproduced metrics against reference: {ref_path} (tolerance={args.tolerance})...")

    try:
        reference_metrics = json.loads(ref_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[ERROR] Failed to parse reference metrics JSON: {e}", file=sys.stderr)
        return 1

    mismatches = compare_metrics(
        reproduced=reproduced_metrics,
        reference=reference_metrics,
        path="",
        tolerance=args.tolerance,
    )

    if mismatches:
        print("\n" + "!" * 78, file=sys.stderr)
        print(f"[FAILURE] Reproduction comparison FAILED with {len(mismatches)} mismatch(es):", file=sys.stderr)
        print("!" * 78, file=sys.stderr)
        for m in mismatches:
            print(f"  - {m}", file=sys.stderr)
        print("!" * 78, file=sys.stderr)
        return 1

    if not args.quiet:
        print("\n" + format_summary_table(reproduced_metrics))
        print(f"\n[PASS] All metrics reproduced successfully! Exact match with {ref_path} (tol={args.tolerance}).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
