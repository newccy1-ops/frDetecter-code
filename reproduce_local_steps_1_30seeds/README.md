# Stage 1: fixed 30-seed reproduction

Run from repository root:

```powershell
python run_demo.py stage1
```

This recomputes MNIST / Logistic Regression, 50 IID clients (25 honest, 25
low-resource attackers), local_steps=1, batch64, SGD lr0.10, 8 communication
rounds, attack from round5, reference6, validation7, and strict cosine<0.1.
The validation probe runs before regular round7 and starts from saved post-round6
FedAvg. "Observation-only" means the probe does not affect normal FedAvg;
it does NOT mean proof verification is disabled in the separate Stage-2 entry.

Seeds are 20260915..20260944. The runner writes newly generated per_run.csv,
client_level.csv, run_audits.json and summary.json under results/validation_round_7/.
No prior results are required or included. Reported metrics are Stage-1 metrics;
legacy noncryptographic helper verdicts inside the shared simulation are not ZKP.

The training/attack/cosine implementation is the same source used in the completed
experiments. See the root README for environment, expected outcomes and scope.
