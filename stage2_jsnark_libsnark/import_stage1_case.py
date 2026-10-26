"""Import only frozen Stage-1 data/model/upload, never old keys or proofs."""
import argparse
import json
import os
from pathlib import Path
import shutil
from build_backend import ROOT, save, sha

PAYLOADS = (
    'server/stage1_case.json', 'public/stage1_case.json',
    'server/model.json', 'public/model.json',
    'server/submitted_update.json', 'client_private/submitted_update.json',
    'client_private/captured_batch.json', 'evaluation.json',
)
SUMMARY = ROOT.parent/'reproduce_local_steps_1_30seeds/results/validation_round_7/summary.json'

def inspect(source, seed, client_id):
    source = source.resolve(strict=True)
    allowed_roots = [(ROOT/'runs').resolve(), (ROOT.parent/'stage2_zkp_single_client/runs').resolve()]
    if not any(source!=allowed and source.is_relative_to(allowed) for allowed in allowed_roots):
        raise ValueError('Expected a dedicated local Stage-1 capture/backend run')
    marker=source/'capture_complete.json'
    report_path=marker if marker.is_file() else source/'report.json'
    report = json.loads(report_path.read_text(encoding='utf-8'))
    case = json.loads((source/'server/stage1_case.json').read_text(encoding='utf-8'))
    if report['status'] != 'PASS' or (case['seed'], case['client_id']) != (seed, client_id):
        raise AssertionError('Source run not PASS or wrong identity')
    if not case['suspicious'] or not case['cosine_similarity']<case['threshold']:
        raise AssertionError('Source is not Stage-1 suspicious')
    evaluation=json.loads((source/'evaluation.json').read_text(encoding='utf-8'))
    if evaluation['ground_truth_role']!='honest':
        raise AssertionError('This demonstration supports selected honest FP recovery only')
    # Ground truth selects demo cases; it is never passed to the cryptographic verifier.
    if SUMMARY.is_file():
        prior = json.loads(SUMMARY.read_text(encoding='utf-8'))
        matches = [r for r in prior['false_positives'] if (r['seed'], r['client_id']) == (seed, client_id)]
        if len(matches)!=1:
            raise AssertionError('Capture is absent from current Stage-1 natural FP results')
        record=matches[0]
        if case['cosine_similarity']!=record['cosine_similarity'] or case['submitted_update_sha256']!=record['validation_update_hash']:
            raise AssertionError('Captured update differs from current Stage-1 result')
    probe = case['validation_probe_audit']
    if not probe['probe_before_any_regular_subsequent_round'] or not probe['main_fl_trajectory_unchanged_by_probe']:
        raise AssertionError('Frozen probe audit failed')
    return dict(source_run=str(source), seed=seed, client_id=client_id,
                stage1_replayed=False, imported_payload_sha256={p:sha(source/p) for p in PAYLOADS},
                stage1_summary_path=str(SUMMARY) if SUMMARY.is_file() else None,
                stage1_summary_sha256=sha(SUMMARY) if SUMMARY.is_file() else None,
                old_cryptographic_artifacts_imported=False)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-run',type=Path,required=True)
    parser.add_argument('--seed',type=int,required=True)
    parser.add_argument('--client-id',type=int,required=True)
    args=parser.parse_args()
    root=Path(os.environ['FRDETECTER_ZKP_RUN_DIR']).resolve(strict=True)
    if root == (ROOT/'runs').resolve() or not root.is_relative_to((ROOT/'runs').resolve()):
        raise ValueError('Dedicated new-backend run required')
    audit=inspect(args.source_run,args.seed,args.client_id)
    source=Path(audit['source_run'])
    for name,expected in audit['imported_payload_sha256'].items():
        target=root/name
        target.parent.mkdir(parents=True,exist_ok=True)
        if target.exists():raise FileExistsError(target)
        shutil.copyfile(source/name,target)
        if sha(target)!=expected or sha(source/name)!=expected:raise AssertionError('Payload changed')
    save(root/'stage1_import_audit.json',audit)
    print(json.dumps({'imported':True,'stage1_replayed':False,'seed':args.seed,'client_id':args.client_id}))

if __name__=='__main__':main()
