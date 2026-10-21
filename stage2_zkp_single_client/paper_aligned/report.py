"""Summarize only completed, checked NEW runs; never relabel old proofs."""
import hashlib
import json
from pathlib import Path


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        while block:=stream.read(8*1024*1024):
            h.update(block)
    return h.hexdigest()


def write_report(root: Path, phases: list):
    read=lambda name:json.loads((root/name).read_text(encoding='utf-8'))
    case=read('server/stage1_case.json')
    result=read('public/verification.json')
    tests=read('public/negative_tests.json')
    compute=read('client_private/compute_audit.json')
    if result['verify_output']!=1 or not result['cryptographic_verification'] or not tests['all_passed']:
        raise RuntimeError('No successful cryptographic verification/test evidence')
    if not all(tests['tests'].values()) or any(p['exit_code'] for p in phases):
        raise RuntimeError('An execution phase or security regression failed')
    for name,expected in result['verified_file_sha256'].items():
        if digest(root/name)!=expected:
            raise RuntimeError('Verified proof/response package changed after acceptance')
    if read('server/session_state.json')['status']!='CONSUMED':
        raise RuntimeError('Challenge was not consumed')
    report=dict(status='PASS',schema=case['schema'],seed=case['seed'],client_id=case['client_id'],
                executed_rounds=dict(reference=6,validation=7),stage1_cosine=case['cosine_similarity'],
                stage1_suspicious=case['suspicious'],server_verification=result,
                selected_client_final_prediction='benign',phases=phases,compute_audit=compute,
                security_tests=tests,proof_bytes=(root/'public/proof.json').stat().st_size,
                all_suspicious_clients_proven=False,full_two_stage_ablation_completed=False,
                historical_paper_tables_execution_proven=False,
                proof_scope='One-batch fixed-point approximation bound to the original Stage-1 upload; not exact IEEE-754',
                single_batch_sampling_degenerate=True,remote_data_authenticity_proven=False,
                historical_execution_time_or_no_witness_reuse_proven=False,
                backend_matches_paper=False,source_hashes=read('source_hashes.json'),
                runtime_config=read('run_config.json'))
    (root/'report.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return report
