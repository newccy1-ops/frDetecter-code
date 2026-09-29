"""Two-stage functional control-flow demo for MNIST low-resource free-riding.

The second stage is a non-cryptographic functional verifier used only to
reproduce frDetecter's control flow. It provides no zero-knowledge,
cryptographic soundness, privacy, or zk-SNARK security guarantees.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import inspect
import json
import math
import random
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import numpy as np
from torch_runtime_compat import preload_system_vc_runtime

preload_system_vc_runtime()

import torch
from torch import Tensor, nn
from torch.utils.data import DataLoader, Dataset, Subset, TensorDataset
from torchvision import datasets


@dataclass(frozen=True)
class DemoConfig:
    """All runnable-demo configuration, with non-paper values clearly marked."""

    num_clients: int = 50  # Required by this demo request.
    num_attackers: int = 25  # Required by the requested 50% free-rider ratio.
    attack_start_paper_round: int = 5  # Paper experiment setting; paper_round is explicitly 1-based.
    device: str = "cpu"  # DEMO_ASSUMPTION: lowest-cost, broadly reproducible device.
    data_root: str = "data"  # DEMO_ASSUMPTION: local MNIST cache location.
    output_path: str = "artifacts/reference_validation_cosine_report.json"
    iid_partition: bool = True  # DEMO_ASSUMPTION: paper does not specify the client partition strategy.
    partition_type: str = "IID"  # DEMO_ASSUMPTION: paper does not specify IID/Non-IID partitioning.
    dirichlet_alpha: float | None = None  # DEMO_ASSUMPTION: used only for label-based Non-IID sweeps.
    seed: int = 20260915  # DEMO_ASSUMPTION: paper does not specify a random seed.
    local_epochs: int = 1  # DEMO_ASSUMPTION: paper does not specify local epochs.
    # DEMO_ASSUMPTION: None processes the full configured local epoch.  A
    # positive value caps local training at that many minibatches per call.
    local_steps: int | None = None
    capture_batch_indices: bool = False  # DEMO_ASSUMPTION: audit-only instrumentation for batch-overlap sweeps.
    batch_relationship: str = "independent"  # DEMO_ASSUMPTION: independent/identical/disjoint audit condition.
    batch_size: int = 64  # DEMO_ASSUMPTION: paper does not specify batch size.
    learning_rate: float = 0.10  # DEMO_ASSUMPTION: paper does not specify learning rate.
    optimizer: str = "SGD"  # DEMO_ASSUMPTION: paper only says gradient descent, not an optimizer variant.
    communication_rounds: int = 8  # DEMO_ASSUMPTION: smoke-test length; paper does not specify total FedAvg rounds.
    clients_per_round: int = 50  # DEMO_ASSUMPTION: paper does not specify per-round client participation.
    num_workers: int = 0  # DEMO_ASSUMPTION: simple deterministic data loading.
    # DEMO_ASSUMPTION: paper does not specify attacker-identity sampling; sample once from this seed.
    # DEMO_ASSUMPTION: paper does not specify the distribution or magnitude of the random fabricated update.
    # A standard-Gaussian direction is normalized and scaled to the round-4 genuine-update median L2 norm.
    attack_direction_distribution: str = "standard_gaussian_normalized"
    attack_norm_source_paper_round: int = 4
    reference_paper_round: int = 6  # Paper experiment setting; explicit 1-based paper-round numbering.
    validation_paper_round: int = 8  # DEMO_ASSUMPTION: reproducible probe round; not a paper-fixed parameter.
    cosine_epsilon: float = 1e-12  # DEMO_ASSUMPTION: numerical nonzero-norm guard, not a detector value.
    # DEMO_ASSUMPTION: the validation probe is observation-only and does not modify the main FL trajectory.
    validation_probe_observation_only: bool = True
    # DEMO_ASSUMPTION: threshold=0.1 is used only for this functional reproduction.
    # The original manuscript does not explicitly specify the numerical threshold.
    threshold: float = 0.1


class LogisticRegression(nn.Module):
    """Multiclass logistic regression for flattened 28 x 28 MNIST images."""

    def __init__(self) -> None:
        super().__init__()
        self.linear = nn.Linear(28 * 28, 10)

    def forward(self, images: Tensor) -> Tensor:
        return self.linear(images.reshape(images.shape[0], 28 * 28))


class IndexedSubset(Dataset):
    """Expose original MNIST indices without changing a Subset's samples/order."""

    def __init__(self, subset: Subset) -> None:
        self.subset = subset

    def __len__(self) -> int:
        return len(self.subset)

    def __getitem__(self, index: int):
        image, label = self.subset[index]
        return image, label, self.subset.indices[index]


# Per-process cache only.  ``ToTensor`` for a uint8 MNIST image produces its
# float32 value divided by 255, so this removes repeated image-conversion cost
# without changing samples, values, labels, partitions, loader shuffle, or the
# FL/attack/detection protocol.  Each independent batch worker owns its cache.
_MNIST_TENSOR_CACHE: dict[str, tuple[TensorDataset, TensorDataset]] = {}


def load_mnist_tensor_datasets(data_root: str) -> tuple[TensorDataset, TensorDataset]:
    cached = _MNIST_TENSOR_CACHE.get(data_root)
    if cached is not None:
        return cached
    raw_train = datasets.MNIST(data_root, train=True, download=True, transform=None)
    raw_test = datasets.MNIST(data_root, train=False, download=True, transform=None)
    train_dataset = TensorDataset(raw_train.data.unsqueeze(1).to(torch.float32).div(255.0), raw_train.targets.clone())
    test_dataset = TensorDataset(raw_test.data.unsqueeze(1).to(torch.float32).div(255.0), raw_test.targets.clone())
    _MNIST_TENSOR_CACHE[data_root] = (train_dataset, test_dataset)
    return train_dataset, test_dataset


def set_reproducible_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)
    torch.set_num_threads(1)


def make_iid_client_subsets(dataset: Dataset, num_clients: int, seed: int) -> list[Subset]:
    """Create equal-size, disjoint IID client subsets using one seeded permutation."""
    if len(dataset) % num_clients != 0:
        raise ValueError(f"Dataset size {len(dataset)} must be divisible by num_clients {num_clients}.")
    indices = np.random.default_rng(seed).permutation(len(dataset)).tolist()
    samples_per_client = len(dataset) // num_clients
    return [
        Subset(dataset, indices[index * samples_per_client : (index + 1) * samples_per_client])
        for index in range(num_clients)
    ]


def make_dirichlet_client_subsets(dataset: Dataset, num_clients: int, seed: int, alpha: float, minimum_client_samples: int = 64) -> tuple[list[Subset], int]:
    """Seeded label-based Dirichlet partition with no duplication or padding."""
    if alpha <= 0.0:
        raise ValueError("Dirichlet alpha must be positive.")
    if not isinstance(dataset, TensorDataset):
        raise TypeError("The Dirichlet partition requires tensor MNIST labels.")
    labels = dataset.tensors[1].detach().cpu().numpy()
    for resample_count in range(10_000):
        rng = np.random.default_rng(seed + resample_count)
        client_indices: list[list[int]] = [[] for _ in range(num_clients)]
        for label in np.unique(labels):
            label_indices = rng.permutation(np.flatnonzero(labels == label))
            proportions = rng.dirichlet(np.full(num_clients, alpha))
            raw_counts = proportions * len(label_indices)
            counts = np.floor(raw_counts).astype(int)
            remainder = len(label_indices) - int(counts.sum())
            if remainder:
                # Stable tie-breaking remains deterministic under this RNG.
                order = np.argsort(-(raw_counts - counts), kind="stable")
                counts[order[:remainder]] += 1
            offsets = np.concatenate(([0], np.cumsum(counts)))
            for client_id in range(num_clients):
                client_indices[client_id].extend(label_indices[offsets[client_id] : offsets[client_id + 1]].tolist())
        if min(map(len, client_indices)) >= minimum_client_samples:
            return [Subset(dataset, indices) for indices in client_indices], resample_count
    raise RuntimeError(f"Unable to sample a Dirichlet(alpha={alpha}) partition with at least {minimum_client_samples} samples/client.")


def make_client_subsets(dataset: Dataset, config: DemoConfig) -> tuple[list[Subset], dict[str, int | float | str]]:
    if config.partition_type == "IID":
        subsets = make_iid_client_subsets(dataset, config.num_clients, config.seed)
        return subsets, {"partition_type": "IID", "alpha": None, "partition_resample_count": 0}
    if config.partition_type != "dirichlet" or config.dirichlet_alpha is None:
        raise ValueError("Partition configuration is invalid.")
    subsets, resamples = make_dirichlet_client_subsets(dataset, config.num_clients, config.seed, config.dirichlet_alpha)
    return subsets, {"partition_type": "dirichlet", "alpha": config.dirichlet_alpha, "partition_resample_count": resamples}


def sample_fixed_attacker_ids(config: DemoConfig) -> list[int]:
    """Sample attacker identities once; callers keep this list for every round."""
    rng = np.random.default_rng(config.seed + 1)
    return sorted(rng.choice(config.num_clients, size=config.num_attackers, replace=False).tolist())


def check_partition(subsets: list[Subset], dataset_size: int) -> dict:
    client_sizes = [len(subset) for subset in subsets]
    all_indices = [index for subset in subsets for index in subset.indices]
    result: dict[str, int | bool] = {
        "client_count": len(subsets),
        "client_sample_counts": client_sizes,
        "all_clients_have_data": all(size > 0 for size in client_sizes),
        "min_client_samples": min(client_sizes),
        "max_client_samples": max(client_sizes),
        "client_subsets_non_overlapping": len(all_indices) == len(set(all_indices)),
        "assigned_sample_count": len(all_indices),
        "train_dataset_sample_count": dataset_size,
        "assigned_sample_count_matches_dataset": len(all_indices) == dataset_size,
    }
    if not all(bool(result[key]) for key in ("all_clients_have_data", "client_subsets_non_overlapping", "assigned_sample_count_matches_dataset")):
        raise AssertionError(f"Client partition check failed: {result}")
    return result


def check_model_dimensions(model: LogisticRegression) -> dict[str, int | bool]:
    logits = model(torch.zeros(2, 1, 28, 28))
    result: dict[str, int | bool] = {
        "input_features": model.linear.in_features,
        "output_classes": model.linear.out_features,
        "test_batch_output_shape_is_2_by_10": tuple(logits.shape) == (2, 10),
    }
    if not result["test_batch_output_shape_is_2_by_10"]:
        raise AssertionError(f"Incorrect model output shape: {tuple(logits.shape)}")
    return result


def make_loader(dataset: Dataset, batch_size: int, shuffle: bool, seed: int, num_workers: int) -> DataLoader:
    return DataLoader(dataset, batch_size=batch_size, shuffle=shuffle, generator=torch.Generator().manual_seed(seed), num_workers=num_workers)


def clone_state(state: dict[str, Tensor]) -> dict[str, Tensor]:
    return {name: value.detach().cpu().clone() for name, value in state.items()}


def all_finite(state: dict[str, Tensor]) -> bool:
    return all(torch.isfinite(value).all().item() for value in state.values())


def update_l2_norm(global_state: dict[str, Tensor], local_state: dict[str, Tensor]) -> float:
    return math.sqrt(sum(torch.sum((local_state[name] - tensor).to(torch.float64) ** 2).item() for name, tensor in global_state.items()))


def states_identical(left: dict[str, Tensor], right: dict[str, Tensor]) -> bool:
    return left.keys() == right.keys() and all(torch.equal(left[name], right[name]) for name in left)


def flatten_update(base_state: dict[str, Tensor], client_state: dict[str, Tensor]) -> Tensor:
    """Flatten all trainable model updates in the fixed state-dict key order."""
    return torch.cat([(base_state[name] - client_state[name]).reshape(-1).to(torch.float64) for name in base_state])


def sha256_tensor(tensor: Tensor) -> str:
    contiguous = tensor.detach().cpu().contiguous()
    hasher = hashlib.sha256()
    hasher.update(str(tuple(contiguous.shape)).encode("utf-8"))
    hasher.update(str(contiguous.dtype).encode("utf-8"))
    hasher.update(contiguous.numpy().tobytes())
    return hasher.hexdigest()


def sha256_state(state: dict[str, Tensor]) -> str:
    hasher = hashlib.sha256()
    for name, tensor in state.items():
        hasher.update(name.encode("utf-8"))
        hasher.update(sha256_tensor(tensor).encode("utf-8"))
    return hasher.hexdigest()


def safe_cosine(reference_update: Tensor, validation_update: Tensor, epsilon: float) -> tuple[float | None, float, float]:
    reference_norm = torch.linalg.vector_norm(reference_update).item()
    validation_norm = torch.linalg.vector_norm(validation_update).item()
    if reference_norm <= epsilon or validation_norm <= epsilon:
        return None, reference_norm, validation_norm
    cosine = torch.dot(reference_update, validation_update).item() / (reference_norm * validation_norm)
    if not math.isfinite(cosine):
        raise FloatingPointError("Non-finite cosine similarity.")
    if cosine < -1.0 - 1e-10 or cosine > 1.0 + 1e-10:
        raise AssertionError(f"Cosine similarity outside numerical range: {cosine}")
    return max(-1.0, min(1.0, cosine)), reference_norm, validation_norm


def cosine_group_statistics(records: list[dict]) -> dict:
    values = np.array([record["cosine_similarity"] for record in records if record["cosine_similarity"] is not None], dtype=float)
    if len(values) != len(records):
        return {"count": len(records), "valid_cosine_count": len(values), "undefined_cosine_count": len(records) - len(values)}
    return {
        "count": len(values),
        "valid_cosine_count": len(values),
        "undefined_cosine_count": 0,
        "minimum": float(values.min()),
        "maximum": float(values.max()),
        "mean": float(values.mean()),
        "median": float(np.median(values)),
        "standard_deviation_population": float(values.std(ddof=0)),
        "q1": float(np.percentile(values, 25)),
        "q3": float(np.percentile(values, 75)),
        # Observation-only cuts for comparison with the paper's descriptive ranges; never used for detection.
        "observation_counts": {
            "cosine_gt_0_1": int(np.sum(values > 0.1)),
            "cosine_gt_0_and_le_0_1": int(np.sum((values > 0.0) & (values <= 0.1))),
            "cosine_le_0": int(np.sum(values <= 0.0)),
        },
    }


def write_client_cosines_csv(records: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "client_id",
        "role",
        "reference_update_norm",
        "validation_update_norm",
        "validation_update_hash",
        "cosine_similarity",
        "threshold",
        "suspicious",
        "ground_truth_positive",
        "classification_result",
        "stage1_suspicious",
        "integrity_check_triggered",
        "training_transcript_exists",
        "training_executed",
        "integrity_verification",
        "integrity_verification_failures",
        "final_prediction",
        "final_classification_result",
    ]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)


def add_first_stage_decisions(records: list[dict], threshold: float) -> list[dict]:
    """Apply the manuscript rule cosine < threshold without using ground truth.

    The role is read only after the independent suspicious decision, solely to
    label the experimental confusion matrix.
    """
    decided_records: list[dict] = []
    for source_record in records:
        record = dict(source_record)
        cosine = record["cosine_similarity"]
        if cosine is None:
            raise ValueError(f"Cannot apply first-stage decision to undefined cosine for client={record['client_id']}.")
        suspicious = cosine < threshold  # Strict inequality required by the manuscript rule.
        ground_truth_positive = record["role"] == "attacker"
        if ground_truth_positive and suspicious:
            classification_result = "TP"
        elif ground_truth_positive:
            classification_result = "FN"
        elif suspicious:
            classification_result = "FP"
        else:
            classification_result = "TN"
        record.update(
            {
                "threshold": threshold,
                "suspicious": suspicious,
                "ground_truth_positive": ground_truth_positive,
                "classification_result": classification_result,
            }
        )
        decided_records.append(record)
    return decided_records


def compute_classification_metrics(records: list[dict], free_rider_ratio: float, classification_field: str) -> dict:
    counts = {label: sum(record[classification_field] == label for record in records) for label in ("TP", "FP", "TN", "FN")}
    tp, fp, tn, fn = (counts[label] for label in ("TP", "FP", "TN", "FN"))
    if tp + fn == 0 or fp + tn == 0 or tp + fp == 0:
        raise ZeroDivisionError("This smoke test requires nonzero denominators for DSR, FPR, and Precision.")
    dsr = tp / (tp + fn)
    fpr = fp / (fp + tn)
    precision = tp / (tp + fp)
    recall = dsr
    f1_direct = 2 * tp / (2 * tp + fp + fn)
    f1_precision_recall = 2 * precision * recall / (precision + recall)
    f1_derived = 2 * free_rider_ratio * dsr / (
        free_rider_ratio * (1 + dsr) + (1 - free_rider_ratio) * fpr
    )
    if not all(math.isfinite(value) for value in (dsr, fpr, precision, recall, f1_direct, f1_precision_recall, f1_derived)):
        raise FloatingPointError("Non-finite classification metric.")
    checks = {
        "tp_plus_fn_equals_25": tp + fn == 25,
        "fp_plus_tn_equals_25": fp + tn == 25,
        "all_confusion_cells_sum_to_50": tp + fp + tn + fn == 50,
        "f1_direct_equals_f1_precision_recall": math.isclose(f1_direct, f1_precision_recall, rel_tol=0.0, abs_tol=1e-12),
        "f1_direct_equals_f1_derived": math.isclose(f1_direct, f1_derived, rel_tol=0.0, abs_tol=1e-12),
    }
    if not all(checks.values()):
        raise AssertionError(f"Classification metric consistency audit failed: {checks}")
    decimals = {
        "DSR": dsr,
        "FPR": fpr,
        "Precision": precision,
        "Recall": recall,
        "F1_direct": f1_direct,
        "F1_precision_recall": f1_precision_recall,
        "F1_derived_from_DSR_FPR_ratio": f1_derived,
    }
    return {
        "positive_class": "free_rider_attacker",
        "free_rider_ratio": free_rider_ratio,
        "confusion_matrix": counts,
        "decimal": decimals,
        "percent": {name: value * 100 for name, value in decimals.items()},
        "consistency_audit": checks,
    }


def is_valid_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def verify_training_integrity(
    client_id: int,
    transcript: dict | None,
    expected_validation_input_model_hash: str,
    expected_update_hash: str,
) -> tuple[str, list[str]]:
    """Functional transcript consistency check; this is not a cryptographic proof."""
    if transcript is None:
        return "FAIL", ["missing_training_transcript"]
    failures: list[str] = []
    required_fields = (
        "client_id",
        "validation_input_model_hash",
        "num_batches_processed",
        "num_optimizer_steps",
        "initial_loss",
        "final_loss",
        "update_hash",
        "training_executed",
    )
    if any(field not in transcript for field in required_fields):
        failures.append("missing_required_field")
    if transcript.get("client_id") != client_id:
        failures.append("client_id_mismatch")
    if transcript.get("training_executed") is not True:
        failures.append("training_not_executed")
    if transcript.get("validation_input_model_hash") != expected_validation_input_model_hash:
        failures.append("validation_input_model_hash_mismatch")
    if not is_valid_sha256(transcript.get("validation_input_model_hash")):
        failures.append("invalid_validation_input_model_hash")
    if not isinstance(transcript.get("num_batches_processed"), int) or transcript.get("num_batches_processed", 0) <= 0:
        failures.append("invalid_batch_count")
    if not isinstance(transcript.get("num_optimizer_steps"), int) or transcript.get("num_optimizer_steps", 0) <= 0:
        failures.append("invalid_optimizer_step_count")
    if not all(math.isfinite(transcript.get(field, float("nan"))) for field in ("initial_loss", "final_loss")):
        failures.append("nonfinite_loss")
    if transcript.get("update_hash") != expected_update_hash:
        failures.append("update_hash_mismatch")
    if not is_valid_sha256(transcript.get("update_hash")) or not is_valid_sha256(expected_update_hash):
        failures.append("invalid_update_hash")
    return ("PASS" if not failures else "FAIL"), failures


def run_functional_integrity_stage(
    records: list[dict], transcripts: dict[int, dict], validation_input_model_hash: str
) -> tuple[list[dict], dict, dict[int, dict]]:
    """Trigger the functional verifier only for the dynamic Stage-1 suspicious list."""
    final_records: list[dict] = []
    triggered_count = pass_count = fail_count = 0
    for source_record in records:
        record = dict(source_record)
        client_id = record["client_id"]
        stage1_suspicious = bool(record["suspicious"])
        transcript = transcripts.get(client_id)
        if not stage1_suspicious:
            integrity_check_triggered = False
            integrity_verification = "NOT_TRIGGERED"
            verification_failures: list[str] = []
            final_prediction = "benign"
        else:
            integrity_check_triggered = True
            triggered_count += 1
            integrity_verification, verification_failures = verify_training_integrity(
                client_id,
                transcript,
                validation_input_model_hash,
                record["validation_update_hash"],
            )
            if integrity_verification == "PASS":
                pass_count += 1
                final_prediction = "benign"
            else:
                fail_count += 1
                final_prediction = "free_rider"
        record.update(
            {
                "stage1_suspicious": stage1_suspicious,
                "integrity_check_triggered": integrity_check_triggered,
                "training_transcript_exists": transcript is not None,
                "training_executed": bool(transcript and transcript.get("training_executed") is True),
                "integrity_verification": integrity_verification,
                "integrity_verification_failures": verification_failures,
                "final_prediction": final_prediction,
            }
        )
        final_records.append(record)
    suspicious_count = sum(record["stage1_suspicious"] for record in final_records)
    if triggered_count != suspicious_count or pass_count + fail_count != triggered_count:
        raise AssertionError("Second-stage trigger audit failed.")
    if any(record["integrity_check_triggered"] for record in final_records if not record["stage1_suspicious"]):
        raise AssertionError("A non-suspicious client entered Stage 2.")
    return final_records, {
        "stage1_suspicious_count": suspicious_count,
        "integrity_check_triggered_count": triggered_count,
        "integrity_verification_pass_count": pass_count,
        "integrity_verification_fail_count": fail_count,
    }


def add_final_classification_results(records: list[dict]) -> list[dict]:
    """Use ground truth only after final predictions exist, for experiment metrics."""
    evaluated_records: list[dict] = []
    for source_record in records:
        record = dict(source_record)
        ground_truth_positive = bool(record["ground_truth_positive"])
        predicted_positive = record["final_prediction"] == "free_rider"
        if ground_truth_positive and predicted_positive:
            result = "TP"
        elif ground_truth_positive:
            result = "FN"
        elif predicted_positive:
            result = "FP"
        else:
            result = "TN"
        record["final_classification_result"] = result
        evaluated_records.append(record)
    return evaluated_records


def train_one_client(
    global_state: dict[str, Tensor],
    client_dataset: Dataset,
    config: DemoConfig,
    paper_round: int,
    client_index: int,
    capture_training_transcript: bool = False,
    validation_input_model_hash: str | None = None,
    capture_batch_indices: bool = False,
    forced_batch_indices: list[int] | None = None,
) -> tuple[dict[str, Tensor], float, dict | None, dict[str, int]]:
    """The only function that trains on client data and performs optimizer steps."""
    model = LogisticRegression().to(config.device)
    model.load_state_dict(global_state)
    optimizer = torch.optim.SGD(model.parameters(), lr=config.learning_rate)
    criterion = nn.CrossEntropyLoss()
    if forced_batch_indices is not None:
        if len(forced_batch_indices) != config.batch_size:
            raise ValueError("A forced batch must contain exactly batch_size unique samples.")
        if len(set(forced_batch_indices)) != len(forced_batch_indices) or not set(forced_batch_indices).issubset(set(client_dataset.indices)):
            raise ValueError("Forced batch indices are invalid for this client.")
        loader_dataset: Dataset = Subset(client_dataset.dataset, forced_batch_indices)
    else:
        loader_dataset = client_dataset
    if capture_batch_indices:
        loader_dataset = IndexedSubset(loader_dataset if isinstance(loader_dataset, Subset) else client_dataset)
    loader = make_loader(loader_dataset, config.batch_size, True, config.seed + paper_round * config.num_clients + client_index, config.num_workers)
    model.train()
    loss_total, sample_total = 0.0, 0
    num_batches_processed = 0
    num_optimizer_steps = 0
    initial_loss: float | None = None
    final_loss: float | None = None
    processed_indices: list[int] = []
    for _ in range(config.local_epochs):
        for batch in loader:
            if config.local_steps is not None and num_batches_processed >= config.local_steps:
                break
            if capture_batch_indices:
                images, labels, batch_indices = batch
                processed_indices.extend(int(index) for index in batch_indices.tolist())
            else:
                images, labels = batch
            images, labels = images.to(config.device), labels.to(config.device)
            optimizer.zero_grad()
            loss = criterion(model(images), labels)
            if not torch.isfinite(loss):
                raise FloatingPointError(f"Non-finite local loss at paper_round={paper_round}, client={client_index}.")
            if initial_loss is None:
                initial_loss = loss.item()
            loss.backward()
            optimizer.step()
            loss_total += loss.item() * labels.shape[0]
            sample_total += labels.shape[0]
            num_batches_processed += 1
            num_optimizer_steps += 1
            final_loss = loss.item()
        if config.local_steps is not None and num_batches_processed >= config.local_steps:
            break
    local_state = clone_state(model.state_dict())
    if not all_finite(local_state):
        raise FloatingPointError(f"Non-finite local model parameter at paper_round={paper_round}, client={client_index}.")
    transcript = None
    if capture_training_transcript:
        if validation_input_model_hash is None or initial_loss is None or final_loss is None:
            raise AssertionError("A captured training transcript requires a validation input hash and nonempty training.")
        update_hash = sha256_tensor(flatten_update(global_state, local_state))
        transcript = {
            "client_id": client_index,
            "validation_input_model_hash": validation_input_model_hash,
            "num_batches_processed": num_batches_processed,
            "num_samples_processed": sample_total,
            "num_optimizer_steps": num_optimizer_steps,
            "initial_loss": initial_loss,
            "final_loss": final_loss,
            "update_hash": update_hash,
            "training_executed": True,
        }
    if sample_total == 0:
        raise AssertionError("Local training processed no samples.")
    return local_state, loss_total / sample_total, transcript, {
        "num_batches_processed": num_batches_processed,
        "num_samples_processed": sample_total,
        "num_optimizer_steps": num_optimizer_steps,
        "batch_indices": processed_indices if capture_batch_indices else None,
    }


def fabricate_random_local_model(
    global_state: dict[str, Tensor], attack_update_norm: float, config: DemoConfig, paper_round: int, client_index: int
) -> dict[str, Tensor]:
    """Create theta_attacker = theta_global + normalized random delta.

    This function has no dataset, model forward pass, loss, local training
    function, or optimizer. It is the low-resource attack branch.
    """
    if not math.isfinite(attack_update_norm) or attack_update_norm <= 0.0:
        raise ValueError("attack_update_norm must be finite and positive.")
    generator = torch.Generator(device="cpu").manual_seed(config.seed + 100_000 + paper_round * config.num_clients + client_index)
    direction = {name: torch.randn(tensor.shape, generator=generator, dtype=tensor.dtype) for name, tensor in global_state.items()}
    direction_norm = math.sqrt(sum(torch.sum(tensor.to(torch.float64) ** 2).item() for tensor in direction.values()))
    if direction_norm == 0.0:
        raise AssertionError("Sampled random direction has zero norm.")
    local_state = {name: global_state[name] + direction[name] * (attack_update_norm / direction_norm) for name in global_state}
    if not all_finite(local_state):
        raise FloatingPointError(f"Non-finite fabricated update at paper_round={paper_round}, client={client_index}.")
    if not math.isclose(update_l2_norm(global_state, local_state), attack_update_norm, rel_tol=1e-6, abs_tol=1e-7):
        raise AssertionError("Fabricated update norm differs from frozen target.")
    return local_state


def fedavg(local_states: list[dict[str, Tensor]], sample_counts: list[int]) -> tuple[dict[str, Tensor], float]:
    """Apply the paper's data-size-weighted FedAvg equation to every upload."""
    if not local_states or len(local_states) != len(sample_counts):
        raise ValueError("FedAvg requires one local state and one sample count per participant.")
    weights = [count / sum(sample_counts) for count in sample_counts]
    if not math.isclose(sum(weights), 1.0, rel_tol=0.0, abs_tol=1e-12):
        raise AssertionError(f"FedAvg weights do not sum to one: {sum(weights)}")
    aggregated = {
        name: sum((state[name] * weight for state, weight in zip(local_states, weights, strict=True)), torch.zeros_like(local_states[0][name]))
        for name in local_states[0]
    }
    if not all_finite(aggregated):
        raise FloatingPointError("FedAvg produced non-finite global parameters.")
    return aggregated, sum(weights)


@torch.no_grad()
def evaluate(model: nn.Module, dataset: Dataset, config: DemoConfig) -> tuple[float, float]:
    loader = make_loader(dataset, config.batch_size, False, config.seed, config.num_workers)
    criterion = nn.CrossEntropyLoss(reduction="sum")
    model.eval()
    loss_total, correct = 0.0, 0
    for images, labels in loader:
        images, labels = images.to(config.device), labels.to(config.device)
        logits = model(images)
        loss_total += criterion(logits, labels).item()
        correct += (logits.argmax(dim=1) == labels).sum().item()
    return loss_total / len(dataset), correct / len(dataset)


def mean_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    if not all(math.isfinite(value) for value in values):
        raise FloatingPointError("Encountered non-finite update norm.")
    return float(np.mean(values))


def median_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    if not all(math.isfinite(value) for value in values):
        raise FloatingPointError("Encountered non-finite update norm.")
    return float(np.median(values))


def assert_round_audit(
    paper_round: int, attack_active: bool, normal_train_calls: int, attacker_local_train_calls: int, attacker_attack_calls: int, config: DemoConfig
) -> None:
    """Make the no-local-training guarantee explicit and executable."""
    if not attack_active:
        assert normal_train_calls == config.num_clients
        assert attacker_local_train_calls == config.num_attackers
        assert attacker_attack_calls == 0
        return
    assert paper_round >= config.attack_start_paper_round
    assert normal_train_calls == config.num_clients - config.num_attackers
    assert attacker_local_train_calls == 0
    assert attacker_attack_calls == config.num_attackers


def run_validation_probe(
    reference_model: dict[str, Tensor],
    client_subsets: list[Subset],
    attacker_id_set: set[int],
    attack_update_norm: float,
    reference_updates: dict[int, Tensor],
    reference_training_audit: list[dict],
    config: DemoConfig,
) -> tuple[list[dict], dict]:
    """Collect validation updates from theta_(r+1), without touching main FL state."""
    records: list[dict] = []
    honest_probe_train_calls = 0
    attacker_probe_train_calls = 0
    attacker_probe_attack_calls = 0
    validation_input_model_hash = sha256_state(reference_model)
    training_transcripts: dict[int, dict] = {}
    reference_batches = {record["client_id"]: record.get("batch_indices") for record in reference_training_audit}
    for client_index in range(config.num_clients):
        is_attacker = client_index in attacker_id_set
        if is_attacker:
            # The probe deliberately skips train_one_client and does not access attacker data.
            client_state = fabricate_random_local_model(
                reference_model, attack_update_norm, config, config.validation_paper_round, client_index
            )
            attacker_probe_attack_calls += 1
        else:
            forced_batch_indices = None
            if config.batch_relationship == "identical":
                forced_batch_indices = reference_batches.get(client_index)
            elif config.batch_relationship == "disjoint":
                reference_indices = reference_batches.get(client_index)
                if reference_indices is None:
                    raise AssertionError("Disjoint validation requires captured reference batch indices.")
                candidates = sorted(set(client_subsets[client_index].indices) - set(reference_indices))
                generator = np.random.default_rng(config.seed + 200_000 + config.validation_paper_round * config.num_clients + client_index)
                forced_batch_indices = generator.choice(candidates, size=config.batch_size, replace=False).tolist()
            client_state, local_loss, transcript, training_stats = train_one_client(
                reference_model,
                client_subsets[client_index],
                config,
                config.validation_paper_round,
                client_index,
                capture_training_transcript=True,
                validation_input_model_hash=validation_input_model_hash,
                capture_batch_indices=config.capture_batch_indices,
                forced_batch_indices=forced_batch_indices,
            )
            if not math.isfinite(local_loss):
                raise FloatingPointError(f"Non-finite honest validation-probe loss for client={client_index}.")
            if transcript is None:
                raise AssertionError("Honest validation training did not produce a transcript.")
            if config.capture_batch_indices:
                transcript["batch_indices"] = training_stats["batch_indices"]
            training_transcripts[client_index] = transcript
            honest_probe_train_calls += 1

        validation_update = flatten_update(reference_model, client_state)
        validation_update_hash = sha256_tensor(validation_update)
        cosine, reference_norm, validation_norm = safe_cosine(
            reference_updates[client_index], validation_update, config.cosine_epsilon
        )
        records.append(
            {
                "client_id": client_index,
                "role": "attacker" if is_attacker else "honest",
                "reference_update_norm": reference_norm,
                "validation_update_norm": validation_norm,
                "cosine_similarity": cosine,
                "validation_update_hash": validation_update_hash,
            }
        )

    if honest_probe_train_calls != config.num_clients - config.num_attackers:
        raise AssertionError("Validation probe did not train all 25 honest clients.")
    if attacker_probe_train_calls != 0 or attacker_probe_attack_calls != config.num_attackers:
        raise AssertionError("Validation probe attacker audit failed.")
    if len(training_transcripts) != config.num_clients - config.num_attackers:
        raise AssertionError("Expected transcripts only for the 25 honest validation-training executions.")
    records.sort(key=lambda record: record["client_id"])
    return records, {
        "validation_paper_round": config.validation_paper_round,
        "probe_base_model": "saved_theta_r_plus_1",
        "validation_input_model_hash": validation_input_model_hash,
        "honest_probe_real_train_calls": honest_probe_train_calls,
        "attacker_probe_real_train_calls": attacker_probe_train_calls,
        "attacker_probe_attack_calls": attacker_probe_attack_calls,
        "undefined_cosine_client_ids": [record["client_id"] for record in records if record["cosine_similarity"] is None],
        "all_50_clients_have_cosine": all(record["cosine_similarity"] is not None for record in records),
    }, training_transcripts


def run_smoke_test(config: DemoConfig, evaluate_round_metrics: bool = True) -> dict:
    if config.num_clients != 50 or config.num_attackers != 25:
        raise ValueError("This requested scenario is fixed at 50 clients with 25 attackers.")
    if config.clients_per_round != config.num_clients:
        raise ValueError("This requested smoke test aggregates all 50 client uploads every round.")
    if config.optimizer != "SGD":
        raise ValueError("This demo implements only the documented SGD DEMO_ASSUMPTION.")
    if config.partition_type == "IID" and not config.iid_partition:
        raise ValueError("IID partition configuration is inconsistent.")
    if config.partition_type == "dirichlet" and (config.iid_partition or config.dirichlet_alpha is None):
        raise ValueError("Dirichlet partition configuration is inconsistent.")
    if config.local_steps is not None and config.local_steps <= 0:
        raise ValueError("local_steps must be positive or None for a full local epoch.")
    if config.batch_relationship not in {"independent", "identical", "disjoint"}:
        raise ValueError("Unknown batch relationship.")
    if config.batch_relationship != "independent" and not config.capture_batch_indices:
        raise ValueError("Non-independent batch relationships require batch-index auditing.")
    if config.attack_norm_source_paper_round != config.attack_start_paper_round - 1:
        raise ValueError("Attack norm source must be the genuine-training round immediately before attack start.")
    if config.reference_paper_round != 6:
        raise ValueError("This paper-round audit is fixed at reference paper round 6.")
    if config.validation_paper_round <= config.reference_paper_round:
        raise ValueError("Validation paper round must occur after reference paper round 6.")
    if config.validation_paper_round > config.communication_rounds:
        raise ValueError("Validation paper round must occur within the smoke-test run.")
    if not config.validation_probe_observation_only:
        raise ValueError("This stage implements only an observation-only validation probe.")

    set_reproducible_seed(config.seed)
    train_dataset, test_dataset = load_mnist_tensor_datasets(config.data_root)
    client_subsets, partition_metadata = make_client_subsets(train_dataset, config)
    partition_check = check_partition(client_subsets, len(train_dataset))
    attacker_ids = sample_fixed_attacker_ids(config)
    attacker_id_set = set(attacker_ids)
    if len(attacker_ids) != config.num_attackers or len(attacker_id_set) != config.num_attackers:
        raise AssertionError("Attacker identity sampling did not yield exactly 25 unique attackers.")

    global_model = LogisticRegression().to(config.device)
    dimension_check = check_model_dimensions(global_model)
    global_state = clone_state(global_model.state_dict())
    attack_update_norm: float | None = None
    reference_input_model: dict[str, Tensor] | None = None
    reference_model: dict[str, Tensor] | None = None
    reference_snapshot_matches_fedavg = False
    reference_updates: dict[int, Tensor] = {}
    reference_honest_training_audit: list[dict[str, int]] = []
    validation_main_start_model: dict[str, Tensor] | None = None
    rounds: list[dict] = []

    for paper_round in range(1, config.communication_rounds + 1):
        attack_active = paper_round >= config.attack_start_paper_round
        if paper_round == config.reference_paper_round:
            # theta_r: server model on entry to paper round 6.
            reference_input_model = clone_state(global_state)
        if paper_round == config.validation_paper_round:
            # This is recorded only to prove the probe does not use the main-trajectory input at its validation round.
            validation_main_start_model = clone_state(global_state)
        local_states, sample_counts, genuine_norms, attacker_norms = [], [], [], []
        real_train_calls = attacker_local_train_calls = attacker_attack_calls = 0
        for client_index in range(config.num_clients):
            is_attacker = client_index in attacker_id_set
            if attack_active and is_attacker:
                # This branch never invokes train_one_client and never reads client data.
                assert attack_update_norm is not None
                local_state = fabricate_random_local_model(global_state, attack_update_norm, config, paper_round, client_index)
                attacker_attack_calls += 1
                attacker_norms.append(update_l2_norm(global_state, local_state))
            else:
                local_state, local_loss, _, training_stats = train_one_client(
                    global_state, client_subsets[client_index], config, paper_round, client_index,
                    capture_batch_indices=config.capture_batch_indices and paper_round == config.reference_paper_round and not is_attacker,
                )
                if not math.isfinite(local_loss):
                    raise FloatingPointError(f"Non-finite genuine local loss at paper_round={paper_round}, client={client_index}.")
                real_train_calls += 1
                attacker_local_train_calls += int(is_attacker)
                genuine_norms.append(update_l2_norm(global_state, local_state))
                if paper_round == config.reference_paper_round and not is_attacker:
                    reference_honest_training_audit.append({"client_id": client_index, **training_stats})
            if not all_finite(local_state):
                raise FloatingPointError(f"Non-finite local upload at paper_round={paper_round}, client={client_index}.")
            local_states.append(local_state)
            # FedAvg receives every upload; attacker IDs are never used to filter aggregation.
            sample_counts.append(len(client_subsets[client_index]))

        assert len(local_states) == config.num_clients
        assert_round_audit(paper_round, attack_active, real_train_calls, attacker_local_train_calls, attacker_attack_calls, config)
        if paper_round == config.attack_norm_source_paper_round:
            attack_update_norm = median_or_none(genuine_norms)
            if attack_update_norm is None or attack_update_norm <= 0.0:
                raise AssertionError("Could not freeze a positive attack_update_norm from round 4.")

        if paper_round == config.reference_paper_round:
            # Save all g_i^r = theta_r - theta_i^(r+1), before FedAvg changes the global model.
            reference_updates = {
                client_index: flatten_update(reference_input_model, local_state)
                for client_index, local_state in enumerate(local_states)
            }
            if len(reference_updates) != config.num_clients:
                raise AssertionError("Reference round did not save all 50 client updates.")

        global_state, weight_sum = fedavg(local_states, sample_counts)
        if paper_round == config.reference_paper_round:
            # theta_(r+1): exact FedAvg result from paper round 6, retained for later probing.
            reference_model = clone_state(global_state)
            if not states_identical(reference_model, global_state):
                raise AssertionError("Saved theta_r_plus_1 differs from post-reference FedAvg model.")
            reference_snapshot_matches_fedavg = True
        if evaluate_round_metrics:
            global_model.load_state_dict(global_state)
            train_loss, train_accuracy = evaluate(global_model, train_dataset, config)
            test_loss, test_accuracy = evaluate(global_model, test_dataset, config)
            if not all(math.isfinite(value) for value in (train_loss, train_accuracy, test_loss, test_accuracy)):
                raise FloatingPointError(f"Non-finite global metric at paper_round={paper_round}.")
        else:
            # Evaluation is observational and cannot affect logistic-regression
            # training, aggregation, attack generation, or the validation probe.
            train_loss = train_accuracy = test_loss = test_accuracy = None
        rounds.append({
            "paper_round": paper_round,
            "attack_active": attack_active,
            # Before round 5 this is all 50 real local-training calls; afterward, the 25 honest-client calls.
            "real_train_calls": real_train_calls,
            "attacker_local_train_calls": attacker_local_train_calls,
            "attacker_attack_calls": attacker_attack_calls,
            "mean_honest_update_l2_norm": mean_or_none(genuine_norms),
            "median_honest_update_l2_norm": median_or_none(genuine_norms),
            "mean_attacker_update_l2_norm": mean_or_none(attacker_norms),
            "median_attacker_update_l2_norm": median_or_none(attacker_norms),
            "frozen_attack_update_l2_norm": attack_update_norm,
            "participating_clients": len(local_states),
            "fedavg_weight_sum": weight_sum,
            "global_parameters_finite": all_finite(global_state),
            "global_train_loss": train_loss,
            "global_train_accuracy": train_accuracy,
            "global_test_loss": test_loss,
            "global_test_accuracy": test_accuracy,
        })

    inactive, active = rounds[:4], rounds[4:]
    if not all(row["real_train_calls"] == 50 and row["attacker_attack_calls"] == 0 and not row["attack_active"] for row in inactive):
        raise AssertionError("Rounds 1-4 attack audit failed.")
    if not all(row["real_train_calls"] == 25 and row["attacker_local_train_calls"] == 0 and row["attacker_attack_calls"] == 25 and row["participating_clients"] == 50 and row["attack_active"] for row in active):
        raise AssertionError("Rounds 5-8 attack audit failed.")
    if reference_input_model is None or reference_model is None or not reference_snapshot_matches_fedavg or len(reference_updates) != config.num_clients:
        raise AssertionError("Reference round 6 audit data is incomplete.")
    if len(reference_honest_training_audit) != config.num_clients - config.num_attackers:
        raise AssertionError("Reference-round honest training-step audit is incomplete.")
    if validation_main_start_model is None:
        raise AssertionError("Validation-round main trajectory input was not recorded.")
    if attack_update_norm is None:
        raise AssertionError("Attack-update norm was not frozen before the validation probe.")

    # The regular round-8 FedAvg flow is complete before this separate observation-only probe starts.
    main_trajectory_before_probe = clone_state(global_state)
    client_cosines, validation_audit, training_transcripts = run_validation_probe(
        reference_model, client_subsets, attacker_id_set, attack_update_norm, reference_updates, reference_honest_training_audit, config
    )
    main_trajectory_unchanged_by_probe = states_identical(main_trajectory_before_probe, global_state)
    if not main_trajectory_unchanged_by_probe:
        raise AssertionError("Observation-only validation probe changed the main FL trajectory.")
    if not validation_audit["all_50_clients_have_cosine"]:
        raise AssertionError(f"Undefined cosine values: {validation_audit['undefined_cosine_client_ids']}")

    # The threshold decision is made from cosine alone; role becomes visible only for evaluation below.
    client_cosines = add_first_stage_decisions(client_cosines, config.threshold)
    honest_cosines = [record for record in client_cosines if record["role"] == "honest"]
    attacker_cosines = [record for record in client_cosines if record["role"] == "attacker"]
    if len(honest_cosines) != 25 or len(attacker_cosines) != 25:
        raise AssertionError("Ground-truth groups do not contain 25 clients each.")
    free_rider_ratio = config.num_attackers / config.num_clients
    first_stage_metrics = compute_classification_metrics(client_cosines, free_rider_ratio, "classification_result")
    client_cosines, integrity_stage_audit = run_functional_integrity_stage(
        client_cosines,
        training_transcripts,
        validation_audit["validation_input_model_hash"],
    )
    client_cosines = add_final_classification_results(client_cosines)
    final_metrics = compute_classification_metrics(client_cosines, free_rider_ratio, "final_classification_result")
    verifier_source = inspect.getsource(verify_training_integrity)
    forbidden_verifier_identifiers = ("attacker_ids", "role", "ground_truth_positive")
    verifier_ground_truth_independent = not any(identifier in verifier_source for identifier in forbidden_verifier_identifiers)
    if not verifier_ground_truth_independent:
        raise AssertionError("Functional verifier source references ground-truth attacker identity.")
    cosine_csv_path = Path(config.output_path).with_name("reference_validation_client_cosines.csv")
    write_client_cosines_csv(client_cosines, cosine_csv_path)
    return {
        "config": asdict(config),
        "attacker_ids": attacker_ids,
        "partition_check": partition_check,
        "partition_metadata": partition_metadata,
        "model_dimension_check": dimension_check,
        "rounds": rounds,
        "attack_audit_passed": True,
        "all_rounds_aggregate_all_50_uploads": all(row["participating_clients"] == 50 for row in rounds),
        "reference_round_audit": {
            "reference_paper_round": config.reference_paper_round,
            "reference_is_paper_round_6": True,
            "saved_reference_update_count": len(reference_updates),
            "theta_r_plus_1_is_post_reference_fedavg_model": reference_snapshot_matches_fedavg,
            "honest_training_step_audit": reference_honest_training_audit,
        },
        "validation_probe_audit": {
            **validation_audit,
            "probe_input_is_saved_theta_r_plus_1": True,
            "probe_input_is_not_validation_round_main_start_model": not states_identical(reference_model, validation_main_start_model),
            # Retained for the already-completed round-8 single-run artifact schema.
            "probe_input_is_not_round_8_main_start_model": not states_identical(reference_model, validation_main_start_model),
            "main_fl_trajectory_unchanged_by_probe": main_trajectory_unchanged_by_probe,
            "probe_is_observation_only": config.validation_probe_observation_only,
        },
        "client_cosines": client_cosines,
        "cosine_group_statistics": {
            "honest": cosine_group_statistics(honest_cosines),
            "attacker": cosine_group_statistics(attacker_cosines),
        },
        "first_stage_threshold": {
            "value": config.threshold,
            "comparison": "cosine_similarity < threshold",
            "demo_assumption": "threshold=0.1 is used only for this functional reproduction. The original manuscript does not explicitly specify the numerical threshold.",
        },
        "first_stage_metrics": first_stage_metrics,
        "functional_integrity_verifier": {
            "demo_assumption": "This stage is a non-cryptographic functional verifier used only to reproduce the control flow of frDetecter. It does not provide zero-knowledge, cryptographic soundness, privacy, or the security guarantees of zk-SNARK.",
            "training_transcript_schema": [
                "client_id",
                "validation_input_model_hash",
                "num_batches_processed",
                "num_samples_processed",
                "num_optimizer_steps",
                "initial_loss",
                "final_loss",
                "update_hash",
                "training_executed",
            ],
            "verifier_ground_truth_independent": verifier_ground_truth_independent,
            "forbidden_identifiers_absent_from_verifier_source": list(forbidden_verifier_identifiers),
        },
        "training_transcripts": [training_transcripts[client_id] for client_id in sorted(training_transcripts)],
        "integrity_stage_audit": integrity_stage_audit,
        "final_frdetecter_metrics": final_metrics,
        "client_cosines_csv_path": str(cosine_csv_path),
    }


def parse_args() -> DemoConfig:
    defaults = DemoConfig()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=defaults.communication_rounds)
    parser.add_argument("--local-epochs", type=int, default=defaults.local_epochs)
    parser.add_argument("--batch-size", type=int, default=defaults.batch_size)
    parser.add_argument("--learning-rate", type=float, default=defaults.learning_rate)
    parser.add_argument("--seed", type=int, default=defaults.seed)
    parser.add_argument("--data-root", default=defaults.data_root)
    parser.add_argument("--output-path", default=defaults.output_path)
    args = parser.parse_args()
    return replace(defaults, communication_rounds=args.rounds, local_epochs=args.local_epochs, batch_size=args.batch_size, learning_rate=args.learning_rate, seed=args.seed, data_root=args.data_root, output_path=args.output_path)


def format_optional(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.6f}"


def main() -> None:
    config = parse_args()
    report = run_smoke_test(config)
    output_path = Path(config.output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("PASS: MNIST FedAvg low-resource free-rider attack smoke test")
    print(f"attacker_ids={report['attacker_ids']}")
    print(json.dumps(report["partition_check"], indent=2))
    for row in report["rounds"]:
        print(
            "paper_round={paper_round} attack_active={attack_active} real_train_calls={real_train_calls} "
            "attacker_local_train_calls={attacker_local_train_calls} attacker_attack_calls={attacker_attack_calls} "
            "honest_mean_norm={honest_mean} honest_median_norm={honest_median} attacker_mean_norm={attacker_mean} "
            "attacker_median_norm={attacker_median} test_loss={global_test_loss:.6f} test_accuracy={global_test_accuracy:.4%} "
            "participants={participating_clients}".format(
                honest_mean=format_optional(row["mean_honest_update_l2_norm"]),
                honest_median=format_optional(row["median_honest_update_l2_norm"]),
                attacker_mean=format_optional(row["mean_attacker_update_l2_norm"]),
                attacker_median=format_optional(row["median_attacker_update_l2_norm"]),
                **row,
            )
        )
    print(f"report={output_path}")


if __name__ == "__main__":
    main()
