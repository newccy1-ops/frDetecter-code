"""Replay the existing Stage 1, capture an ACTUAL natural-FP probe batch.

No changes to Stage-1 modules. Ground truth is confined to demo selection and
evaluation; it is not an input to the Stage-2 public verifier.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from dataclasses import asdict, replace
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / 'reproduce_local_steps_1_30seeds'))
import fedavg_mnist_demo as demo


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed', type=int, required=True)
    parser.add_argument('--client-id', type=int, required=True)
    parser.add_argument('--data-root', type=Path, default=PROJECT/'data')
    args = parser.parse_args()
    root = Path(os.environ['FRDETECTER_ZKP_RUN_DIR']).resolve()
    allowed = PROJECT / 'stage2_zkp_single_client/runs'
    if not root.is_relative_to(allowed.resolve()) or root == allowed.resolve():
        raise ValueError('Dedicated run directory required')

    def write(name, value):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value, indent=2, allow_nan=False)+'\n', encoding='utf-8')

    original = demo.train_one_client
    captured = {}

    def capture(state, dataset, config, paper_round, client_index, **kwargs):
        selected_probe = kwargs.get('capture_training_transcript', False) and client_index == args.client_id
        if selected_probe:
            loader = demo.make_loader(dataset, config.batch_size, True,
                                     config.seed + paper_round*config.num_clients + client_index, config.num_workers)
            images, labels = next(iter(loader))
            pixels = images.reshape(64, 784).mul(255).round().to(demo.torch.int64)
            if not demo.torch.equal(pixels.to(demo.torch.float32).div(255), images.reshape(64, 784)):
                raise AssertionError('Original uint8 pixel capture mismatch')
            batch = dict(pixels=pixels.tolist(), labels=labels.tolist())
            batch_hash = hashlib.sha256(json.dumps(batch, separators=(',', ':')).encode()).hexdigest()
        result = original(state, dataset, config, paper_round, client_index, **kwargs)
        if selected_probe:
            update = demo.flatten_update(state, result[0])
            captured.update(batch=batch, pretraining_batch_sha256=batch_hash,
                            weights=state['linear.weight'].tolist(), bias=state['linear.bias'].tolist(),
                            submitted_update=update.tolist(), input_model_sha256=demo.sha256_state(state),
                            submitted_update_sha256=demo.sha256_tensor(update))
        return result

    config = replace(demo.DemoConfig(), seed=args.seed, local_steps=1, data_root=str(args.data_root.resolve()),
                     output_path=str(root/'client_private/stage1/report.json'))
    if (config.reference_paper_round, config.validation_paper_round) != (6, 7):
        raise AssertionError('Reference/validation must be 6->7')
    demo.train_one_client = capture
    try:
        report = demo.run_smoke_test(config, evaluate_round_metrics=False)
    finally:
        demo.train_one_client = original
    record = next(x for x in report['client_cosines'] if x['client_id'] == args.client_id)
    if not record['stage1_suspicious'] or record['role'] != 'honest':
        raise RuntimeError('Selected case is not a natural honest FP; stop without seed search or tuning')
    probe = report['validation_probe_audit']
    if not probe['probe_before_any_regular_subsequent_round'] or not probe['main_fl_trajectory_unchanged_by_probe']:
        raise AssertionError('Stage-1 timing/state audit failed')
    if captured['submitted_update_sha256'] != record['validation_update_hash'] or captured['input_model_sha256'] != probe['validation_input_model_hash']:
        raise AssertionError('Captured case differs from actual Stage-1 upload')
    previous_path = PROJECT/'reproduce_local_steps_1_30seeds/results/validation_round_7/summary.json'
    previous_match = False
    if previous_path.is_file():
        previous = json.loads(previous_path.read_text(encoding='utf-8'))
        matches = [x for x in previous.get('false_positives', [])
                   if x['seed'] == args.seed and x['client_id'] == args.client_id]
        if matches:
            prior = matches[0]
            if prior['cosine_similarity'] != record['cosine_similarity'] or prior['validation_update_hash'] != record['validation_update_hash']:
                raise AssertionError('Replayed Stage-1 case differs from the completed 30-seed evidence')
            previous_match = True
    case = dict(schema='frdetecter-paper-aligned-v2', seed=args.seed, client_id=args.client_id,
                cosine_similarity=record['cosine_similarity'], threshold=config.threshold, suspicious=True,
                input_model_sha256=captured['input_model_sha256'], submitted_update_sha256=captured['submitted_update_sha256'],
                pretraining_batch_sha256=captured['pretraining_batch_sha256'], protocol=asdict(config),
                validation_probe_audit=probe, eligible_batch_count=1, matches_completed_30_seed_FP=previous_match,
                batch_selection_scope='Single actual validation iteration; singleton sampling, not full-epoch random coverage')
    write('server/stage1_case.json', case)
    write('public/stage1_case.json', case)
    model = dict(weights=captured['weights'], bias=captured['bias'])
    write('server/model.json', model)
    write('public/model.json', model)
    write('server/submitted_update.json', captured['submitted_update'])
    write('client_private/captured_batch.json', {**captured['batch'], 'pretraining_batch_sha256':captured['pretraining_batch_sha256']})
    write('client_private/submitted_update.json', captured['submitted_update'])
    write('evaluation.json', dict(ground_truth_role='honest', selected_client_id=args.client_id,
                                 first_stage_metrics=report['first_stage_metrics'],
                                 note='Existing functional Stage-2 helper verdicts are not ZKP inputs or reported two-stage results'))
    print(json.dumps(dict(exported=True, seed=args.seed, client_id=args.client_id, suspicious=True)))


if __name__ == '__main__':
    main()
