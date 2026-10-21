# Stage 2: actual one-client Groth16 proof

Use the repository-root entry, not a historical run directory:

```powershell
python run_demo.py stage2
python run_demo.py stage2 --all-cases
```

The default is seed20260923/client30. `--all-cases` runs that case plus
seed20260925/client1 and seed20260938/client26 **sequentially**. Each replays the
unchanged Stage-1 protocol, captures the actual submitted update/batch, builds
its own circuit and keys, and generates/checks a genuine Groth16 proof.
No saved model, dataset, previous report, proof, verification key, witness or
proving key is needed from this repository. First use downloads checksum-pinned
public tooling/CRS, and MNIST if absent. Local output is always under runs/.

The four-step implementation is in paper_aligned/: server KeyGen; client
Compute; client Prove; server Verify. The server owns the challenge, pins its
original Stage-1 model/update and VK, and consumes an accepted challenge once.
It does not infer integrity from role labels or a training_executed transcript.

This is the **three honest false-positive recovery demos**, not cryptographic
verification of all 753 suspicious decisions from the 30-seed study. See the root
README and paper_aligned/README for numerical/security/reproduction limitations.
