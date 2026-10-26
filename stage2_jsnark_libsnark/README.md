# Stage 2: Java / jsnark / libsnark

This is the default Stage-2 backend. Java/jsnark constructs the training circuit
and witness; native libsnark performs KeyGen, Prove and independent strong-input-
consistency Verify. The older Circom/snarkjs backend remains available separately.
Only pure encoding/Poseidon helpers and constants are shared with that backend;
its prover, verifier, compiler and old proofs are not used here.

## Install and run

Use the Python/Node environment described in the root README, plus JDK 17 and Git
on PATH. From the repository root on Windows:

```powershell
npm --prefix stage2_zkp_single_client ci --no-audit --no-fund
python stage2_jsnark_libsnark/bootstrap_sources.py
powershell -NoProfile -ExecutionPolicy Bypass -File stage2_jsnark_libsnark/bootstrap_msys2.ps1 -InstallPackages
python run_demo.py stage2 --all-cases
```

MSYS2 is isolated under this backend's ignored `dependencies/`. Upstream jsnark,
libsnark, Gson and the MSYS2 archive are pinned and checked; OS packages are
resolved by the signed package manager, not claimed to be original-paper versions.
On Linux install JDK, Node, Git, CMake, GCC, GMP/OpenSSL development libraries,
then skip the MSYS2 command. Windows is the tested platform.

`build_backend.py` builds automatically on each run. No prebuilt executables,
downloaded libraries, dataset, model, historical report, key, witness or proof is
part of this source release. There is no public CRS download for this backend.

## Actual Stage-1 input, not a replacement update

`python run_demo.py stage2` replays the selected seed of the unchanged Stage-1
protocol, captures the actual validation model, batch and uploaded update, then
proves that update. When a 30-seed summary exists, its cosine and upload hash must
match exactly. A non-suspicious/non-honest selection stops without tuning/search.

To keep Stage 1 and Stage 2 explicitly separate, first run:

```powershell
python run_demo.py stage1-case --seed 20260923 --client-id 30
```

Copy the printed `STAGE1_CASE_DIR`, then use it as the value below:

```powershell
python run_demo.py stage2 --seed 20260923 --client-id 30 --case-dir "<STAGE1_CASE_DIR>"
```

The second command copies only the captured model/batch/upload/metadata, checks
their original tensor and byte hashes, and does not rerun Stage 1. Old keys,
challenge, witness, proof and verification decisions are never imported.

## Frozen mechanism

- MNIST, Linear(784,10), 50 IID clients, 25 low-resource attackers, all participate.
- Single local minibatch, batch64, SGD lr0.1, attack5, reference6, validation7,
  8 communication rounds, threshold0.1 with strict `<`.
- Probe starts from the saved post-round-6 model, before normal round7 training;
  `observation-only` means no FedAvg/trajectory mutation, not absent Stage 2.
- Actual private batch registered with a salted Poseidon commitment before a new
  server nonce; server KeyGen reads public model/circuit, not private data.
- All 7,850 coordinates of the **original** uploaded update are bound. Compute
  uses Q=2^30, degree-6 exponential approximation/five squarings and the existing
  unchanged error/range constraints, not a newly fitted update or tolerance.
- Fresh libsnark Groth16/ALT_BN128 keys and proof; server-owned VK and expected
  public inputs; Verify reads neither private batch/witness nor ground truth.
- Single-use atomic acceptance; wrong metadata/public input, missing/tampered
  proof and correctly recommitted invalid update coordinates are rejected.

Protocol tests: `python stage2_jsnark_libsnark/test_source_contract.py`.
Finished evidence can be checked without new training/proving:
`python stage2_jsnark_libsnark/verify_run.py "<NEW_RUN_DIRECTORY>"`.

Generated `runs/` contains role-separated inputs, `report.json`, logs, private
witness, large keys and `public/proof.bin`. It must stay local and is gitignored.
Run three cases sequentially: native setup/proving needs several GB RAM per case
and keys/intermediates consume multiple GB disk. Plan for at least 16 GB RAM and
30 GB free disk; measured time is hardware-dependent, not a performance promise.

## Scope

The toolchain follows Java/jsnark/libsnark as described in the manuscript. This
does not establish exact author-source reproduction: proof variant/curve,
dependency versions, fixed-point representation/approximation/bounds, commitment
encoding and local circuit-specific trusted setup are engineering choices.
There is no independently audited multiparty setup. The statement is not an
IEEE-754 bitwise proof, remote data provenance, historical execution-time proof,
or proof that a witness/computation was never reused. The single executed batch
makes random batch selection degenerate. The three selected honest FP cases do
not establish all suspicious/attacker decisions, full ablation or historical
Table V execution. Do not publish private batches/witnesses or setup secrets.
