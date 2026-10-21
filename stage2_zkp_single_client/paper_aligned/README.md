# Protocol implementation and boundaries

The published implementation corresponds to the three successfully executed
6->7 honest-client proof cases. This directory contains SOURCE ONLY, not their
experimental reports or proof/key material. Outputs are regenerated on demand.

## Workflow

1. `export_case.py` replays the frozen Stage 1 and captures the selected natural
   honest false positive's actual validation batch, model, and uploaded update.
2. `register_batch.mjs` registers the salted Poseidon batch commitment before
   the server chooses its Stage-2 nonce. It is trusted-local capture, not remote
   data provenance. With local_steps=1 there is exactly ONE eligible iteration.
3. `circuit_builder.mjs` builds a checkpoint-specific circuit from server-owned
   public model/metadata; `keygen.mjs` compiles and generates keys. It uses a
   pinned public Hermez phase1 CRS and one fresh local phase2 contribution.
4. `issue_challenge.mjs` selects the batch and generates server nonce/context.
   The singleton candidate set makes random batch selection degenerate.
5. `compute.mjs` reconstructs the one-batch fixed-point forward/backward/SGD
   relation, without replacing the original Stage-1 upload.
6. `prove.mjs` calculates/checks the witness and creates a real Groth16 proof.
7. `verify.mjs` checks the server's original case/model/update/key/challenge,
   commitments and pairing equations, without reading private batch or labels.
8. `negative_tests.mjs` checks tampered claims/proofs/keys, already-consumed
   sessions and recommitted forged updates that must fail circuit constraints.

The last tests use an IN-MEMORY fresh-state fixture for stateless positive
controls; the real consumed server session is never reset, and real replay
rejection is checked separately. `report.py` only writes PASS after successful
execution, verification, tests and accepted-package hash consistency checks.

## Meaning of the proved relation

The verified `g_c_batch` follows Stage-1 model difference
`theta_base - theta_local`, i.e. a learning-rate-scaled gradient for one SGD
step, subject to float rounding. It is not an unscaled raw loss gradient.
The circuit uses Q=2^30, a degree6 polynomial exp approximation followed by
squaring, bounded integer operations, and ALL 7850 update coordinates.
The nominal per-coordinate discrepancy budget is 10738/Q (~1e-5); actual
circuit weight/bias envelopes are tighter (1/163200 and 1/163840). These are
fixed engineering assumptions, not manuscript parameters. Out-of-domain or
out-of-budget cases fail rather than automatically relaxing the constraints.

`I` is a salted Poseidon batch commitment. The manuscript does not specify the
precise `I -> I_prime` construction; this implementation instantiates `I_prime`
as update commitment plus context binding model, session, manifest, batch and
nonce. This is not a claim of matching an unpublished byte-level protocol.

## Claims NOT made

- No bit-exact IEEE-754/PyTorch training equivalence.
- No proof of historical execution time or prohibition on witness reuse.
- No proof of remote data ownership/provenance or complete-dataset membership.
- No real network authentication, OS-level role isolation or deployment privacy
  guarantee. Server files are assumed trustworthy and not client-rewritable.
- No independently audited multiparty phase2 ceremony.
- No Java/jsnark/libsnark backend reproduction (this uses Circom/snarkjs/BN254).
- No empirical BE-defense result, full Stage-2 coverage or two-stage ablation.
- No evidence that the paper's historical tables already executed ZKP.

Nonce, salt, setup entropy and proof blinding are intentionally fresh; fixed ML
seeds reproduce the selected data/model/update, not identical proof/key bytes.
All base protocol and arithmetic assumptions remain unchanged from the completed
experiments. Packaging only adds portable data-cache I/O and repository entry points.
