"""Portable entry point for the frozen 6->7 Stage-1 and honest-client ZKP demos."""
from __future__ import annotations
import argparse
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parent
CASES = ((20260923, 30), (20260925, 1), (20260938, 26))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='stage', required=True)
    first = sub.add_parser('stage1', help='Recompute the 30-seed Stage-1 study')
    first.add_argument('--workers', type=int, default=4)
    first.add_argument('--data-root', type=Path, default=ROOT/'data')
    capture = sub.add_parser('stage1-case', help='Run one 50-client Stage-1 seed and save one suspicious honest-client capture; no ZKP')
    capture.add_argument('--seed',type=int,default=CASES[0][0])
    capture.add_argument('--client-id',type=int,default=CASES[0][1])
    capture.add_argument('--data-root',type=Path,default=ROOT/'data')
    second = sub.add_parser('stage2', help='Run the Java/jsnark/libsnark single-client ZKP workflow')
    second.add_argument('--seed', type=int, default=CASES[0][0])
    second.add_argument('--client-id', type=int, default=CASES[0][1])
    second.add_argument('--all-cases', action='store_true', help='Prove the three known honest false-positive cases, sequentially')
    second.add_argument('--data-root', type=Path, default=ROOT/'data')
    second.add_argument('--case-dir',type=Path,help='Use an actual saved stage1-case capture without rerunning Stage 1')
    combined = sub.add_parser('all', help='Stage 1, then the three honest-client ZKP cases; not all suspicious clients')
    combined.add_argument('--workers', type=int, default=4)
    combined.add_argument('--data-root', type=Path, default=ROOT/'data')
    args = parser.parse_args()
    data_root = args.data_root.resolve()
    if args.stage=='stage1-case':
        folder=ROOT/'stage2_jsnark_libsnark/runs'/f'capture_seed{args.seed}_client{args.client_id}_{uuid.uuid4().hex[:12]}'
        subprocess.run([sys.executable,'-u',str(ROOT/'stage2_jsnark_libsnark/export_case.py'),
                        '--seed',str(args.seed),'--client-id',str(args.client_id),
                        '--data-root',str(data_root),'--output-dir',str(folder)],cwd=ROOT,check=True)
        print(f'STAGE1_CASE_DIR={folder}',flush=True)
        return
    if args.stage in ('stage1', 'all'):
        if args.workers < 1:
            parser.error('--workers must be positive')
        subprocess.run([sys.executable, '-u', str(ROOT/'reproduce_local_steps_1_30seeds/run_reproduction.py'),
                        '--data-root', str(data_root), '--workers', str(args.workers)], cwd=ROOT, check=True)
    if args.stage in ('stage2', 'all'):
        if args.stage=='stage2' and args.case_dir and args.all_cases:
            parser.error('--case-dir and --all-cases cannot be combined')
        cases = CASES if args.stage == 'all' or args.all_cases else ((args.seed, args.client_id),)
        for seed, client in cases:
            command=[sys.executable,'-u',str(ROOT/'stage2_jsnark_libsnark/run_stage2.py'),
                     '--seed',str(seed),'--client-id',str(client),'--data-root',str(data_root)]
            if args.stage=='stage2' and args.case_dir:
                command+=['--stage1-source-run',str(args.case_dir.resolve())]
            subprocess.run(command,cwd=ROOT,check=True)


if __name__ == '__main__':
    main()
