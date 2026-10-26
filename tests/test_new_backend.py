"""Release wiring tests: no dataset, setup, training or proof generation."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('release_entry',ROOT/'run_demo.py')
entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)

class NewBackendTests(unittest.TestCase):
    def test_default_stage2_is_jsnark(self):
        with patch.object(sys,'argv',['run_demo.py','stage2']),patch.object(entry.subprocess,'run') as run:
            entry.main()
        command=run.call_args.args[0]
        self.assertIn(str(ROOT/'stage2_jsnark_libsnark/run_stage2.py'),command)
        self.assertNotIn(str(ROOT/'stage2_zkp_single_client/run_paper_aligned.py'),command)

    def test_import_case_does_not_request_stage1_replay(self):
        folder=ROOT/'stage2_jsnark_libsnark/runs/example_capture'
        with patch.object(sys,'argv',['run_demo.py','stage2','--seed','20260925','--client-id','1','--case-dir',str(folder)]),patch.object(entry.subprocess,'run') as run:
            entry.main()
        self.assertEqual(run.call_count,1)
        command=run.call_args.args[0]
        self.assertIn('--stage1-source-run',command)
        self.assertEqual(command[command.index('--stage1-source-run')+1],str(folder.resolve()))

    def test_all_runs_stage1_then_three_sequential_new_backend_jobs(self):
        with patch.object(sys,'argv',['run_demo.py','all']),patch.object(entry.subprocess,'run') as run:
            entry.main()
        commands=[call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands),4)
        self.assertIn(str(ROOT/'reproduce_local_steps_1_30seeds/run_reproduction.py'),commands[0])
        for command,(seed,client) in zip(commands[1:],entry.CASES):
            self.assertIn(str(ROOT/'stage2_jsnark_libsnark/run_stage2.py'),command)
            self.assertEqual(command[command.index('--seed')+1],str(seed))
            self.assertEqual(command[command.index('--client-id')+1],str(client))

    def test_server_verify_has_no_private_inputs(self):
        source=(ROOT/'stage2_jsnark_libsnark/run_stage2.py').read_text()
        verify=next(line for line in source.splitlines() if "phase('libsnark_server_verify'" in line)
        self.assertIn("root/'server/verification_key.bin'",verify)
        self.assertIn("root/'public/proof.bin'",verify)
        self.assertNotIn('client_private',verify)
        self.assertNotIn('evaluation.json',verify)

if __name__=='__main__':unittest.main()
