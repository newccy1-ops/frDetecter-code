"""Fast source-contract checks; these are NOT cryptographic experiment evidence."""
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent

class SourceContract(unittest.TestCase):
    def test_native_real_prover_and_strong_verifier(self):
        source=(ROOT/'native/backend.cpp').read_text()
        self.assertIn('r1cs_gg_ppzksnark_prover<PP>',source)
        self.assertIn('r1cs_gg_ppzksnark_verifier_strong_IC<PP>',source)
        verify=source.split('action == "verify"')[1].split('action == "check"')[0]
        self.assertNotIn('parse(',verify)
        self.assertNotIn('auxiliary',verify)
    def test_jsnark_bound_relation_not_commitment_only(self):
        source=(ROOT/'java/frdetecter/BatchCircuit.java').read_text()
        for token in ('extends CircuitGenerator','expNegative','probability','163200','restrictBitLength(31)',
                      'restrictBitLength(23)','commit(pack(raw,8,30),1,salt)','submitted[7840+k]'):
            self.assertIn(token,source)
    def test_keygen_before_compute_and_no_old_proof(self):
        source=(ROOT/'run_stage2.py').read_text()
        self.assertLess(source.index("phase('libsnark_server_keygen'"),source.index("phase('client_compute'"))
        self.assertIn("clientwork/'batch_sgd.arith'",source)
        self.assertIn('protected_hashes()!=protected',source)
        for name in ROOT.glob('*.mjs'):
            self.assertNotIn("from 'snarkjs'",name.read_text())
    def test_export_keeps_stage1_frozen(self):
        source=(ROOT/'export_case.py').read_text()
        self.assertIn('(6, 7)',source)
        self.assertIn('local_steps=1',source)
        self.assertIn('previous_match',source)
        self.assertIn("captured['submitted_update_sha256'] != record['validation_update_hash']",source)

if __name__=='__main__':unittest.main()
