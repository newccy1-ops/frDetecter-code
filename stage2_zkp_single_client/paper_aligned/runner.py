"""Explicit opt-in execution; this module never runs experiments on import."""
from __future__ import annotations
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
from .config import Protocol

SOURCE = Path(__file__).resolve().parent
MODULE = SOURCE.parent


def save(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, allow_nan=False)+'\n', encoding='utf-8')


def main():
    defaults = Protocol()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed', type=int, default=defaults.seed)
    parser.add_argument('--client-id', type=int, default=defaults.client_id)
    parser.add_argument('--data-root', type=Path, default=MODULE.parent/'data', help='MNIST cache; downloads if missing')
    args = parser.parse_args()
    protocol = Protocol(seed=args.seed, client_id=args.client_id)
    if not 0 <= args.client_id < 50:
        parser.error('client-id must be in 0..49')
    node = shutil.which('node')
    npm = shutil.which('npm.cmd') or shutil.which('npm')
    if not node or not npm:
        raise RuntimeError('Node.js/npm required; no training has started')
    # Always isolate a new run. No old proof, witness, key, or result is reused.
    base = (MODULE/'runs').resolve()
    base.mkdir(exist_ok=True)
    root = base/f'paper_v2_seed{args.seed}_client{args.client_id}_{uuid.uuid4().hex[:12]}'
    if not root.resolve().is_relative_to(base):
        raise RuntimeError('Invalid run directory')
    root.mkdir(exist_ok=False)
    env = dict(os.environ, FRDETECTER_ZKP_RUN_DIR=str(root), FRDETECTER_PYTHON=sys.executable)
    phases = []
    save(root/'run_config.json', asdict(protocol))
    sources = [*SOURCE.glob('*.py'), *SOURCE.glob('*.mjs'), MODULE/'run_paper_aligned.py',
               MODULE/'circuits/arithmetic.circom',
               MODULE.parent/'reproduce_local_steps_1_30seeds/fedavg_mnist_demo.py']
    save(root/'source_hashes.json', {str(p.relative_to(MODULE.parent)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})
    save(root/'report.json', {'status':'RUNNING','run_directory':str(root)})
    print(f'New isolated run: {root}', flush=True)

    def phase(name, command, cwd=SOURCE):
        log = root/'logs'/f'{name}.log'
        log.parent.mkdir(exist_ok=True)
        start = time.monotonic()
        print(f'START {name}; log={log}', flush=True)
        with log.open('w', encoding='utf-8') as stream:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
        entry = dict(phase=name,seconds=time.monotonic()-start,exit_code=result.returncode)
        phases.append(entry)
        save(root/'logs/phases.json', phases)
        if result.returncode:
            raise RuntimeError(f'{name} failed; inspect {log}; no parameters are changed automatically')
        print(f'PASS {name}', flush=True)

    try:
        if not all((MODULE/'node_modules'/name/'package.json').is_file() for name in ('circom2','circomlib','circomlibjs','snarkjs')):
            phase('dependencies',[npm,'ci','--no-audit','--no-fund'],MODULE)
        phase('stage1_export',[sys.executable,'-u',str(SOURCE/'export_case.py'),'--seed',str(args.seed),'--client-id',str(args.client_id),
                               '--data-root',str(args.data_root.resolve())])
        phase('register_batch',[node,'register_batch.mjs'])
        phase('keygen_build',[node,'circuit_builder.mjs'])
        phase('keygen_compile',[node,'--max-old-space-size=8192','keygen.mjs','compile'])
        phase('crs_check',[node,str(MODULE/'download_ptau.mjs')],MODULE)
        phase('keygen_setup',[node,'--max-old-space-size=8192','keygen.mjs','setup'])
        phase('keygen_contribute',[node,'--max-old-space-size=4096','keygen.mjs','contribute'])
        phase('server_challenge',[node,'issue_challenge.mjs'])
        phase('client_compute',[node,'compute.mjs'])
        phase('client_witness',[node,'--max-old-space-size=4096','prove.mjs','witness'])
        phase('client_constraint_check',[node,'--max-old-space-size=4096','prove.mjs','check'])
        phase('client_prove',[node,'--max-old-space-size=8192','prove.mjs','prove'])
        phase('server_verify',[node,'verify.mjs'])
        phase('negative_tests',[node,'--max-old-space-size=4096','negative_tests.mjs'])
        from .report import write_report
        write_report(root, phases)
        print(f'PASS single-client proof; report={root / "report.json"}', flush=True)
    except Exception as error:
        save(root/'report.json', {'status':'FAIL','error':str(error),'phases':phases,
                                'scope':'Execution/infrastructure failure is not a measured detector false positive',
                                'run_directory':str(root)})
        raise
