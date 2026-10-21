"""Central engineering assumptions; no import-time experiments."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Protocol:
    # DEMO_ASSUMPTION: choose the FIRST natural FP in the completed 6->7 study,
    # not a seed search or threshold modification. Override together via CLI.
    seed: int = 20260923
    client_id: int = 30
    reference_round: int = 6
    validation_round: int = 7
    # DEMO_ASSUMPTION: preserve the audited Stage-1 settings exactly.
    communication_rounds: int = 8
    local_steps: int = 1
    batch_size: int = 64
    learning_rate: float = 0.10
    threshold: float = 0.1
    # DEMO_ASSUMPTION: the original paper gives no field/encoding/error budget.
    fixed_point_bits: int = 30
    nominal_error_units: int = 10738
    nonce_bytes: int = 16
    salt_bytes: int = 16
    curve_workers: int = 4
    proof_system: str = 'Groth16/BN254 via Circom/snarkjs'
