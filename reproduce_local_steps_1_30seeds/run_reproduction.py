"""30-seed local_steps=1 unit, corrected to adjacent validation round 7.

This unit fixes every protocol setting to the previously audited MNIST
functional Demo after the documented round-8 to round-7 correction. It does not sweep
other local-step counts or tune any parameter.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, replace
from pathlib import Path
from statistics import fmean, pstdev
import sys

from fedavg_mnist_demo import DemoConfig, run_smoke_test


RUNS = 30
BASE_SEED = 20260915
LOCAL_STEPS = 1
UNIT_ROOT = Path(__file__).resolve().parent
DEFAULT_DATA_ROOT = UNIT_ROOT.parent / "data"
RESULTS_ROOT = UNIT_ROOT / "results" / "validation_round_7"

RUN_FIELDS = [
    "run_id", "seed", "honest_cosine_min", "honest_cosine_max",
    "honest_cosine_mean", "honest_cosine_median",
    "honest_cosine_std_population", "honest_cosine_q1", "honest_cosine_q3",
    "attacker_cosine_min", "attacker_cosine_max", "attacker_cosine_mean",
    "attacker_cosine_median", "attacker_cosine_std_population",
    "attacker_cosine_q1", "attacker_cosine_q3", "honest_lt_0_1",
    "honest_in_0_1_to_0_4", "honest_gt_0_4", "attacker_ge_0_1",
    "TP", "FP", "TN", "FN", "DSR", "FPR", "Precision", "F1",
]


def _check_config(config: DemoConfig) -> None:
    """Prove this unit changes only seed, local steps, I/O locations."""
    base, got = asdict(DemoConfig()), asdict(config)
    permitted = {"seed", "local_steps", "data_root", "output_path"}
    changed = {key: (base[key], got[key]) for key in base if base[key] != got[key] and key not in permitted}
    if changed:
        raise AssertionError(f"Unexpected protocol change: {changed}")
    if not (
        config.local_steps == LOCAL_STEPS
        and config.communication_rounds == 8
        and config.reference_paper_round == 6
        and config.validation_paper_round == 7
        and config.batch_size == 64
        and config.learning_rate == 0.10
    ):
        raise AssertionError("Fixed protocol audit failed")


def _worker(run_id: int, data_root: str, temp_root: str) -> tuple[int, dict]:
    config = replace(
        DemoConfig(),
        seed=BASE_SEED + run_id,
        local_steps=LOCAL_STEPS,
        data_root=data_root,
        output_path=str(Path(temp_root) / str(run_id) / "temporary_report.json"),
    )
    _check_config(config)
    report = run_smoke_test(config, evaluate_round_metrics=False)

    reference = report["reference_round_audit"]
    validation = report["validation_probe_audit"]
    if not (
        reference["reference_paper_round"] == 6
        and reference["theta_r_plus_1_is_post_reference_fedavg_model"]
        and validation["validation_paper_round"] == 7
        and validation["probe_base_model"] == "saved_theta_r_plus_1"
        and validation["probe_is_observation_only"]
        and validation["main_fl_trajectory_unchanged_by_probe"]
        and validation["validation_is_immediately_after_reference"]
        and validation["probe_executed_before_validation_round_regular_training"]
        and validation["probe_input_matches_validation_round_main_start_model"]
    ):
        raise AssertionError("Reference/validation semantic audit failed")

    reference_steps = reference["honest_training_step_audit"]
    validation_steps = report["training_transcripts"]
    if len(reference_steps) != 25 or len(validation_steps) != 25:
        raise AssertionError("Expected 25 honest reference and validation updates")
    if any(item["num_batches_processed"] != 1 for item in reference_steps + validation_steps):
        raise AssertionError("local_steps=1 audit failed")
    return run_id, report


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=RUN_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _row(run_id: int, report: dict) -> dict:
    honest = report["cosine_group_statistics"]["honest"]
    attacker = report["cosine_group_statistics"]["attacker"]
    records = report["client_cosines"]
    honest_records = [record for record in records if record["role"] == "honest"]
    attacker_records = [record for record in records if record["role"] == "attacker"]
    confusion = report["first_stage_metrics"]["confusion_matrix"]
    metrics = report["first_stage_metrics"]["decimal"]
    return {
        "run_id": run_id,
        "seed": BASE_SEED + run_id,
        "honest_cosine_min": honest["minimum"],
        "honest_cosine_max": honest["maximum"],
        "honest_cosine_mean": honest["mean"],
        "honest_cosine_median": honest["median"],
        "honest_cosine_std_population": honest["standard_deviation_population"],
        "honest_cosine_q1": honest["q1"],
        "honest_cosine_q3": honest["q3"],
        "attacker_cosine_min": attacker["minimum"],
        "attacker_cosine_max": attacker["maximum"],
        "attacker_cosine_mean": attacker["mean"],
        "attacker_cosine_median": attacker["median"],
        "attacker_cosine_std_population": attacker["standard_deviation_population"],
        "attacker_cosine_q1": attacker["q1"],
        "attacker_cosine_q3": attacker["q3"],
        "honest_lt_0_1": sum(record["cosine_similarity"] < 0.1 for record in honest_records),
        "honest_in_0_1_to_0_4": sum(0.1 < record["cosine_similarity"] <= 0.4 for record in honest_records),
        "honest_gt_0_4": sum(record["cosine_similarity"] > 0.4 for record in honest_records),
        "attacker_ge_0_1": sum(record["cosine_similarity"] >= 0.1 for record in attacker_records),
        **confusion,
        "DSR": metrics["DSR"],
        "FPR": metrics["FPR"],
        "Precision": metrics["Precision"],
        "F1": metrics["F1_direct"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 1))
    args = parser.parse_args()
    data_root = args.data_root.resolve()
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)

    reports: dict[int, dict] = {}
    with tempfile.TemporaryDirectory(prefix="frdetecter_local_steps_1_") as temporary:
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(_worker, run_id, str(data_root), temporary) for run_id in range(RUNS)]
            for completed, future in enumerate(as_completed(futures), 1):
                run_id, report = future.result()
                reports[run_id] = report
                print(f"completed={completed}/{RUNS} run_id={run_id}", flush=True)

    rows = [_row(run_id, reports[run_id]) for run_id in range(RUNS)]
    pooled = {key: sum(row[key] for row in rows) for key in ("TP", "FP", "TN", "FN")}
    if not (pooled["TP"] + pooled["FN"] == 750 and pooled["FP"] + pooled["TN"] == 750):
        raise AssertionError(f"Pooled decision audit failed: {pooled}")

    all_honest = [float(record["cosine_similarity"]) for report in reports.values() for record in report["client_cosines"] if record["role"] == "honest"]
    all_attackers = [float(record["cosine_similarity"]) for report in reports.values() for record in report["client_cosines"] if record["role"] == "attacker"]
    summary = {
        "status": "PASS",
        "reported_stage": "Stage 1 only; existing functional-helper verdicts are not used; no ZKP executed",
        "study": "Fixed local_steps=1, 30-seed reproduction unit.",
        "seed_rule": "seed = 20260915 + run_id, run_id = 0,...,29",
        "fixed_protocol": {
            "dataset": "MNIST", "model": "Logistic Regression", "clients": 50,
            "honest_clients": 25, "attackers": 25, "partition": "IID",
            "local_steps": 1, "batch_size": 64, "optimizer": "SGD",
            "learning_rate": 0.10, "attack_start_paper_round": 5,
            "communication_rounds": 8, "reference_paper_round": 6, "validation_paper_round": 7,
            "validation_probe_input": "saved_theta_r_plus_1",
            "validation_probe_observation_only": True, "threshold": 0.1,
        },
        "run_count": RUNS,
        "decision_counts": pooled,
        "pooled_metrics": {
            "DSR": pooled["TP"] / (pooled["TP"] + pooled["FN"]),
            "FPR": pooled["FP"] / (pooled["FP"] + pooled["TN"]),
            "Precision": pooled["TP"] / (pooled["TP"] + pooled["FP"]),
            "F1": 2 * pooled["TP"] / (2 * pooled["TP"] + pooled["FP"] + pooled["FN"]),
        },
        "cosine": {
            "honest_mean": fmean(all_honest), "honest_std_population": pstdev(all_honest),
            "honest_min": min(all_honest), "honest_max": max(all_honest),
            "attacker_mean": fmean(all_attackers), "attacker_std_population": pstdev(all_attackers),
            "attacker_min": min(all_attackers), "attacker_max": max(all_attackers),
        },
        "checks": {"runs": len(rows) == 30, "honest_decisions": len(all_honest) == 750, "attacker_decisions": len(all_attackers) == 750},
    }
    # Persist actual Stage-1 evidence before temporary per-run files disappear.
    # Logging only: no training, attack, cosine, or classification changes.
    client_fields = ["run_id", "seed", "client_id", "role", "cosine_similarity",
                     "reference_update_norm", "validation_update_norm", "validation_update_hash",
                     "threshold", "suspicious", "ground_truth_positive", "classification_result"]
    clients = []
    run_audits = []
    for run_id in range(RUNS):
        report = reports[run_id]
        seed = BASE_SEED + run_id
        for record in report["client_cosines"]:
            entry = {"run_id": run_id, "seed": seed, **{key: record[key] for key in client_fields[2:]}}
            if not math.isfinite(entry["cosine_similarity"]):
                raise AssertionError("Non-finite Stage-1 cosine")
            clients.append(entry)
        run_audits.append({"run_id": run_id, "seed": seed, "config": report["config"],
                           "attacker_ids": report["attacker_ids"],
                           "partition_check": report["partition_check"],
                           "reference_round_audit": report["reference_round_audit"],
                           "validation_probe_audit": report["validation_probe_audit"],
                           "all_rounds_aggregate_all_50_uploads": report["all_rounds_aggregate_all_50_uploads"],
                           "attack_audit_passed": report["attack_audit_passed"],
                           "rounds": report["rounds"],
                           "first_stage_metrics": report["first_stage_metrics"]})
    assert len(clients) == 1500
    assert len({(item["run_id"], item["client_id"]) for item in clients}) == 1500
    assert all(sum(item["classification_result"] == key for item in clients) == pooled[key]
               for key in ("TP", "FP", "TN", "FN"))
    summary["false_positives"] = [x for x in clients if x["classification_result"] == "FP"]
    summary["false_negatives"] = [x for x in clients if x["classification_result"] == "FN"]
    summary["runs_with_FP"] = sum(row["FP"] > 0 for row in rows)
    summary["runs_with_FN"] = sum(row["FN"] > 0 for row in rows)
    summary["macro_metrics"] = {key: {"mean": fmean(row[key] for row in rows),
                                      "std_population": pstdev(row[key] for row in rows)}
                                for key in ("DSR", "FPR", "Precision", "F1")}
    summary["checks"]["client_decisions_1500_unique"] = True
    summary["checks"]["client_level_confusion_matches_pooled"] = True
    summary["source_sha256"] = {name: hashlib.sha256((UNIT_ROOT / name).read_bytes()).hexdigest()
                                for name in ("fedavg_mnist_demo.py", "run_reproduction.py", "torch_runtime_compat.py")}
    summary["execution"] = {"python": sys.version, "executable": sys.executable,
                             "workers": args.workers, "per_round_accuracy_evaluation": False}
    with (RESULTS_ROOT / "client_level.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=client_fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(clients)
    (RESULTS_ROOT / "run_audits.json").write_text(json.dumps(run_audits, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    _write_csv(RESULTS_ROOT / "per_run.csv", rows)
    (RESULTS_ROOT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PASS: wrote {RESULTS_ROOT}")


if __name__ == "__main__":
    main()
