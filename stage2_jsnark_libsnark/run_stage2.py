"""Unchanged Stage 1 -> independent Java/jsnark/libsnark Stage-2 experiment."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
from build_backend import ROOT, DEP, native_command, save, sha

PROJECT=ROOT.parent
BASELINE=PROJECT/'stage2_zkp_single_client'
FIELD=21888242871839275222246405745257275088548364400416034343698204186575808495617

def protected_hashes():
    files=[*(BASELINE/'paper_aligned').glob('*.py'),*(BASELINE/'paper_aligned').glob('*.mjs'),
           BASELINE/'circuits/arithmetic.circom',*(PROJECT/'reproduce_local_steps_1_30seeds').glob('*.py')]
    return {str(p.relative_to(PROJECT)):sha(p) for p in files}

def java_config(folder):
    folder.mkdir(parents=True,exist_ok=True)
    (folder/'config.properties').write_text('FIELD_PRIME='+str(FIELD)+'\nPATH_TO_LIBSNARK_EXEC=unused\nRUNNING_GENERATORS_IN_PARALLEL=0\nPRINT_HEX=0\nOUTPUT_VERBOSE=0\nDEBUG_VERBOSE=0\n',encoding='ascii')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed',type=int,default=20260923);parser.add_argument('--client-id',type=int,default=30)
    parser.add_argument('--stage1-source-run',type=Path,help='Import frozen Stage-1 payloads only; no Stage-1 training replay')
    parser.add_argument('--data-root',type=Path,default=PROJECT/'data')
    args=parser.parse_args()
    if not 0<=args.client_id<50:parser.error('client-id must be 0..49')
    if not (DEP/'jsnark').is_dir():raise RuntimeError('Bootstrap pinned dependencies before running; no training started')
    node=shutil.which('node');java=shutil.which('java')
    if not node or not java:raise RuntimeError('Node.js and JDK required')
    root=ROOT/'runs'/f'jsnark_seed{args.seed}_client{args.client_id}_{uuid.uuid4().hex[:12]}'
    root.mkdir(parents=True,exist_ok=False)
    env=dict(os.environ,FRDETECTER_ZKP_RUN_DIR=str(root),PYTHONIOENCODING='utf-8')
    phases=[];start=time.perf_counter();protected=protected_hashes()
    save(root/'protected_source_hashes.json',protected)
    sources=[*ROOT.glob('*.py'),*ROOT.glob('*.mjs'),*ROOT.glob('*.ps1'),*ROOT.glob('*.conf'),
             *(ROOT/'java').rglob('*.java'),*(ROOT/'native').glob('*')]
    save(root/'source_hashes_at_start.json',{str(p.relative_to(ROOT)):sha(p) for p in sources if p.is_file()})
    save(root/'report.json',{'status':'RUNNING','run_directory':str(root),'started_utc':datetime.now(timezone.utc).isoformat()})
    print(f'NEW_JSNARK_RUN={root}',flush=True)

    def phase(name,command,cwd=ROOT,expect_failure=False,required_text=None):
        log=root/'logs'/f'{name}.log';log.parent.mkdir(exist_ok=True)
        print(f'START {name}; log={log}',flush=True)
        begin=time.perf_counter()
        with log.open('w',encoding='utf-8') as stream:
            result=subprocess.run([str(x) for x in command],cwd=cwd,env=env,stdout=stream,stderr=subprocess.STDOUT)
        text=log.read_text(encoding='utf-8',errors='replace')
        ok=result.returncode!=0 if expect_failure else result.returncode==0
        if required_text and required_text not in text:ok=False
        entry={'phase':name,'seconds':time.perf_counter()-begin,'exit_code':result.returncode,'expected_failure':expect_failure,'passed':ok}
        phases.append(entry);save(root/'logs/phases.json',phases)
        if not ok:raise RuntimeError(f'{name} failed; inspect {log}; no tolerance/parameter adjustment is allowed')
        print(f'PASS {name}: {entry["seconds"]:.3f}s',flush=True)
        return text

    classpath=os.pathsep.join([str(ROOT/'build/classes'),str(DEP/'gson-2.11.0.jar')])
    def java_command(action,input_file=None):
        cmd=[java,'-Xmx6g','-cp',classpath,'frdetecter.BatchCircuit',action,root/'server/circuit_spec.json',root/'work/poseidon_constants_opt.json']
        if input_file is not None:cmd.append(input_file)
        return cmd
    exe=ROOT/'build/native'/('fr_backend.exe' if os.name=='nt' else 'fr_backend')
    try:
        phase('build_backend',[sys.executable,'-u',ROOT/'build_backend.py'])
        build=json.loads((ROOT/'build/build_manifest.json').read_text())
        if build['status']!='PASS':raise RuntimeError('Native backend build not confirmed')
        if args.stage1_source_run:
            phase('stage1_import',[sys.executable,'-u',ROOT/'import_stage1_case.py','--source-run',args.stage1_source_run,'--seed',str(args.seed),'--client-id',str(args.client_id)])
            phase('stage1_import_validation',[node,ROOT/'validate_import.mjs'])
        else:
            phase('stage1_export',[sys.executable,'-u',ROOT/'export_case.py','--seed',str(args.seed),'--client-id',str(args.client_id),'--data-root',args.data_root.resolve()])
        phase('register_batch',[node,ROOT/'register_batch.mjs'])
        phase('server_circuit_inputs',[node,ROOT/'prepare_circuit.mjs'])
        serverwork=root/'work/server';java_config(serverwork)
        phase('jsnark_server_compile',java_command('build'),serverwork)
        arith=serverwork/'batch_sgd.arith'
        phase('libsnark_server_keygen',native_command([exe,'keygen',arith,serverwork/'dummy.in',root/'public/evaluation_key.bin',root/'server/verification_key.bin',root/'server/constraint_system.bin']))
        spec=json.loads((root/'server/circuit_spec.json').read_text())
        key={'schema':'frdetecter-paper-aligned-v2','backend':'libsnark/r1cs_gg_ppzksnark/ALT_BN128',
            'input_pins':spec['input_pins'],'arith_sha256':sha(arith),
            'evaluation_key_sha256':sha(root/'public/evaluation_key.bin'),'verification_key_sha256':sha(root/'server/verification_key.bin'),
            'constraint_system_sha256':sha(root/'server/constraint_system.bin'),'backend_executable_sha256':sha(exe),
            'private_batch_read_during_keygen':False,'setup_scope':'Fresh local per-circuit setup; no independent MPC ceremony'}
        save(root/'server/key_record.json',key);save(root/'public/key_record.json',key)
        phase('server_challenge',[node,ROOT/'issue_challenge.mjs'])
        phase('client_compute',[node,ROOT/'compute.mjs'])
        clientwork=root/'client_private/jsnark';java_config(clientwork)
        phase('jsnark_client_witness',java_command('witness',root/'client_private/circuit_input.json'),clientwork)
        if sha(clientwork/'batch_sgd.arith')!=key['arith_sha256']:raise RuntimeError('Client regenerated a different circuit')
        if sha(root/'public/evaluation_key.bin')!=key['evaluation_key_sha256']:raise RuntimeError('Client proving key changed')
        phase('client_response',[node,ROOT/'finalize_response.mjs'])
        phase('libsnark_client_constraint_check',native_command([exe,'check',arith,clientwork/'batch_sgd.in']))
        phase('libsnark_client_prove',native_command([exe,'prove',arith,clientwork/'batch_sgd.in',root/'public/evaluation_key.bin',root/'public/proof.bin',root/'public/primary_inputs.txt']),required_text='PROVE_OK')
        phase('server_envelope_check',[node,ROOT/'check_protocol.mjs'])
        # This Verify process receives no .in file, batch, private witness or GT.
        phase('libsnark_server_verify',native_command([exe,'verify',root/'server/verification_key.bin',root/'server/expected_public_inputs.txt',root/'public/proof.bin']),required_text='VERIFY_ACCEPTED')
        challenge=json.loads((root/'server/challenge.json').read_text())
        # Node canonical hash is frozen by the challenge state; do not use Python
        # JSON formatting as an alternative commitment encoding.
        state=json.loads((root/'server/session_state.json').read_text())
        consumed=root/'server/challenge_consumed.json'
        with consumed.open('x',encoding='utf-8') as stream:json.dump({'challenge_sha256':state['challenge_sha256'],'accepted':True},stream)
        save(root/'server/session_state.json',{'status':'CONSUMED','challenge_sha256':state['challenge_sha256']})
        save(root/'public/verification.json',{'status':'ACCEPTED','verify_output':1,'cryptographic_verification':True,
            'selected_client_prediction':'benign','private_witness_accessed':False,'ground_truth_accessed':False,
            'backend':'libsnark/r1cs_gg_ppzksnark','scope':'One selected actual Stage-1 suspicious client only'})
        phase('protocol_negative_tests',[node,ROOT/'negative_protocol_tests.mjs'])
        # Real cryptographic positive control and changed-public-input rejection.
        phase('native_positive_fixture',native_command([exe,'verify',root/'server/verification_key.bin',root/'server/expected_public_inputs.txt',root/'public/proof.bin']),required_text='VERIFY_ACCEPTED')
        values=(root/'server/expected_public_inputs.txt').read_text().split()
        values[1]=str((int(values[1])+1)%FIELD)
        badpub=root/'work/changed_public_inputs.txt';badpub.write_text('\n'.join(values)+'\n')
        phase('native_wrong_public_rejected',native_command([exe,'verify',root/'server/verification_key.bin',badpub,root/'public/proof.bin']),expect_failure=True,required_text='VERIFY_REJECTED')
        empty=root/'work/empty_proof.bin';empty.write_bytes(b'')
        phase('native_missing_proof_rejected',native_command([exe,'verify',root/'server/verification_key.bin',root/'server/expected_public_inputs.txt',empty]),expect_failure=True,required_text='BACKEND_REJECTED: Invalid serialization')
        tampered=root/'work/tampered_proof.bin';data=bytearray((root/'public/proof.bin').read_bytes());data[0]=ord('!');tampered.write_bytes(data)
        phase('native_tampered_proof_rejected',native_command([exe,'verify',root/'server/verification_key.bin',root/'server/expected_public_inputs.txt',tampered]),expect_failure=True,required_text='BACKEND_REJECTED: Invalid serialization')
        phase('prepare_invalid_updates',[node,ROOT/'prepare_negative_inputs.mjs'])
        for coordinate in (0,2500,7849):
            folder=root/'client_private'/f'negative_{coordinate}';java_config(folder)
            # No host Compute pre-check here: rejection must be from jsnark's
            # actual training constraints, with a correctly recomputed commitment.
            phase(f'jsnark_recommitted_invalid_{coordinate}',java_command('witness',root/f'client_private/invalid_{coordinate}.json'),folder,expect_failure=True,required_text='Error in Split --- The number of bits does not fit')
        if protected_hashes()!=protected:raise RuntimeError('Protected existing source changed')
        case=json.loads((root/'server/stage1_case.json').read_text())
        audit=json.loads((root/'client_private/compute_audit.json').read_text())
        hashes={str(p.relative_to(root)):sha(p) for p in [root/'public/proof.bin',root/'public/response.json',root/'public/public_signals.json',root/'server/verification_key.bin',root/'server/challenge.json',arith]}
        report={'status':'PASS','run_directory':str(root),'seed':args.seed,'client_id':args.client_id,
            'stage1_replayed':not bool(args.stage1_source_run),'stage1_source_run':str(args.stage1_source_run.resolve()) if args.stage1_source_run else None,
            'stage1_cosine':case['cosine_similarity'],'stage1_suspicious':True,'selected_client_final_prediction':'benign',
            'elapsed_seconds':time.perf_counter()-start,'phases':phases,'compute_audit':audit,'verified_file_sha256':hashes,
            'proof_bytes':(root/'public/proof.bin').stat().st_size,'toolchain_aligned':True,
            'backend':'Java/jsnark + libsnark/r1cs_gg_ppzksnark/ALT_BN128','build':build,
            'protected_existing_sources_unchanged':True,'actual_private_batch_proven':True,'cryptographic_verification':True,
            'all_negative_checks_passed':True,'all_suspicious_clients_proven':False,'historical_paper_tables_execution_proven':False,
            'exact_original_implementation_reproduced':False,'data_provenance_proven':False,'historical_execution_or_no_witness_reuse_proven':False,
            'scope':'One actual natural honest FP; same fixed-point tolerance and original upload as old backend; not IEEE-754 equivalence or full ablation'}
        save(root/'report.json',report)
        print(f'PASS_JSNARK_LIBSNARK: {root / "report.json"}',flush=True)
    except BaseException as error:
        save(root/'report.json',{'status':'FAIL','error':repr(error),'phases':phases,'elapsed_seconds':time.perf_counter()-start,
            'run_directory':str(root),'protected_existing_sources_unchanged':protected_hashes()==protected,
            'scope':'Infrastructure/implementation failure is not an empirical free-rider classification'})
        raise

if __name__=='__main__':main()
