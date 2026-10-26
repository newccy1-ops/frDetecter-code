"""Read-only evidence audit of a finished new-backend run (no proving/training)."""
import argparse
import json
from pathlib import Path
from build_backend import ROOT, sha

def audit(root):
    if not root.resolve().is_relative_to((ROOT/'runs').resolve()):raise ValueError('Not this backend runs/')
    report=json.loads((root/'report.json').read_text())
    if report['status']!='PASS':raise AssertionError('Run not PASS')
    for name,expected in report['verified_file_sha256'].items():
        if sha(root/name)!=expected:raise AssertionError('Evidence changed: '+name)
    protected=json.loads((root/'protected_source_hashes.json').read_text())
    for name,expected in protected.items():
        if sha(ROOT.parent/name)!=expected:raise AssertionError('Existing backend/Stage1 changed: '+name)
    phases={p['phase']:p for p in report['phases']}
    for name in ('libsnark_server_keygen','jsnark_client_witness','libsnark_client_prove','libsnark_server_verify'):
        if phases[name]['exit_code']!=0:raise AssertionError(name)
    strings={
        'libsnark_client_prove':'PROVE_OK upstream=libsnark/r1cs_gg_ppzksnark',
        'libsnark_server_verify':'VERIFY_ACCEPTED',
        'native_wrong_public_rejected':'VERIFY_REJECTED',
        'native_missing_proof_rejected':'BACKEND_REJECTED: Invalid serialization',
        'native_tampered_proof_rejected':'BACKEND_REJECTED: Invalid serialization',
    }
    for coordinate in (0,2500,7849):
        strings[f'jsnark_recommitted_invalid_{coordinate}']='Error in Split --- The number of bits does not fit'
    for phase,text in strings.items():
        if text not in (root/'logs'/f'{phase}.log').read_text(encoding='utf-8',errors='replace'):
            raise AssertionError('Expected success/rejection cause missing: '+phase)
    state=json.loads((root/'server/session_state.json').read_text())
    if state['status']!='CONSUMED' or not (root/'server/challenge_consumed.json').exists():raise AssertionError('Not consumed')
    tests=json.loads((root/'public/protocol_negative_tests.json').read_text())
    if not tests['all_passed'] or not all(tests['tests'].values()):raise AssertionError('Protocol negative tests')
    original=Path(report['stage1_source_run']) if report.get('stage1_source_run') else None
    compared_original=False
    if original is not None:
        imported=json.loads((root/'stage1_import_audit.json').read_text())
        for name,expected in imported['imported_payload_sha256'].items():
            if sha(root/name)!=expected or sha(original/name)!=expected:raise AssertionError('Imported/source payload changed: '+name)
        if json.loads((root/'stage1_import_validation.json').read_text())['status']!='PASS':raise AssertionError('Import validation failed')
        for name in ('stage1_case.json','model.json','submitted_update.json'):
            new=json.loads((root/'server'/name).read_text())
            old=json.loads((original/'server'/name).read_text())
            if name=='stage1_case.json':
                new['protocol'].pop('output_path',None)
                old['protocol'].pop('output_path',None)
            if new!=old:raise AssertionError('Old/new case or original upload differs: '+name)
        new=json.loads((root/'client_private/captured_batch.json').read_text())
        old=json.loads((original/'client_private/captured_batch.json').read_text())
        if new!=old:raise AssertionError('Actual old/new private batch differs')
        compared_original=True
    return {'status':'PASS','strict_log_rejection_causes_checked':True,'evidence_hashes_checked':True,
            'protected_sources_unchanged':True,'old_new_stage1_payloads_compared_and_identical':compared_original,
            'scope':'Read-only evidence check; no new proof/experiment and no replay-state reset'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run_directory',type=Path);args=p.parse_args()
    print(json.dumps(audit(args.run_directory),indent=2))
