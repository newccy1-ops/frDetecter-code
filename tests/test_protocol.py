"""Fast source/protocol checks; no stored experimental results are required."""
from __future__ import annotations
from dataclasses import replace
import importlib.util
import math
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'reproduce_local_steps_1_30seeds'))
import fedavg_mnist_demo as demo


class ProtocolTests(unittest.TestCase):
    def test_frozen_rounds_and_parameters(self):
        c = replace(demo.DemoConfig(), local_steps=1)
        self.assertEqual((c.reference_paper_round,c.validation_paper_round,c.communication_rounds),(6,7,8))
        self.assertEqual((c.num_clients,c.num_attackers,c.clients_per_round),(50,25,50))
        self.assertEqual((c.batch_size,c.local_steps,c.learning_rate,c.optimizer),(64,1,.1,'SGD'))
        self.assertTrue(c.validation_probe_observation_only)

    def test_strict_threshold(self):
        records=[dict(client_id=i,role='honest',cosine_similarity=x) for i,x in enumerate((.099,.1,.101))]
        result=demo.add_first_stage_decisions(records,.1)
        self.assertEqual([x['suspicious'] for x in result],[True,False,False])

    def test_cosine_formula(self):
        x=demo.torch.tensor([1.,0.],dtype=demo.torch.float64)
        y=demo.torch.tensor([0.,1.],dtype=demo.torch.float64)
        self.assertEqual(demo.safe_cosine(x,y,1e-12)[0],0.)

    def test_weighted_fedavg(self):
        states=[{'w':demo.torch.tensor([1.,3.])},{'w':demo.torch.tensor([5.,7.])}]
        state,weight_sum=demo.fedavg(states,[1,3])
        self.assertTrue(demo.torch.equal(state['w'],demo.torch.tensor([4.,6.])))
        self.assertTrue(math.isclose(weight_sum,1.))

    def test_stage2_keeps_real_pairing_verifier(self):
        source=(ROOT/'stage2_zkp_single_client/paper_aligned/verify.mjs').read_text(encoding='utf-8')
        self.assertIn('groth16.verify(expected.vkey,publicSignals,proof)',source)
        self.assertNotIn("read(root,'client_private/",source)


if __name__=='__main__':
    unittest.main()
