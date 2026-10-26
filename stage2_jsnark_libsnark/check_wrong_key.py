"""Native cryptographic wrong-VK control, without touching real session state.

Generates an unrelated tiny test circuit/key (not another FL/client experiment)
and checks that the real proof is rejected by that well-formed verification key.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
from build_backend import ROOT, native_command, save, sha

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run_directory',type=Path);args=p.parse_args()
    root=args.run_directory.resolve()
    if not root.is_relative_to((ROOT/'runs').resolve()):raise ValueError('Not a new-backend run')
    report=json.loads((root/'report.json').read_text())
    if report['status']!='PASS':raise AssertionError('Finish the real run first')
    folder=root/'work/wrong_key_control';folder.mkdir(exist_ok=False)
    exe=ROOT/'build/native'/('fr_backend.exe' if os.name=='nt' else 'fr_backend')
    # Same public-input arity, but an unrelated tiny relation and fresh key.
    (folder/'tiny.arith').write_text('total 5\ninput 0\ninput 1\ninput 2\ninput 3\ninput 4\nassert in 2 <1 2> out 1 <3>\n',encoding='ascii')
    (folder/'dummy.in').write_text('0 1\n',encoding='ascii')
    def run(name,arguments):
        log=folder/(name+'.log')
        with log.open('w',encoding='utf-8') as stream:
            r=subprocess.run(native_command([exe,*arguments]),stdout=stream,stderr=subprocess.STDOUT)
        return r.returncode,log.read_text(encoding='utf-8',errors='replace')
    code,text=run('keygen',['keygen',folder/'tiny.arith',folder/'dummy.in',folder/'pk.bin',folder/'vk.bin',folder/'cs.bin'])
    if code or 'KEYGEN_OK' not in text:raise AssertionError('Wrong-key fixture generation failed')
    code,text=run('verify_wrong_key',['verify',folder/'vk.bin',root/'server/expected_public_inputs.txt',root/'public/proof.bin'])
    if code==0 or 'VERIFY_REJECTED' not in text:raise AssertionError('Real proof not cryptographically rejected under different VK')
    code,text=run('verify_correct_key',['verify',root/'server/verification_key.bin',root/'server/expected_public_inputs.txt',root/'public/proof.bin'])
    if code or 'VERIFY_ACCEPTED' not in text:raise AssertionError('Correct-key positive control failed')
    save(root/'public/wrong_key_control.json',{'status':'PASS','well_formed_unrelated_VK_rejected_by_native_pairing_verifier':True,
        'original_VK_positive_control_accepted':True,'real_session_state_untouched':True,
        'wrong_vk_sha256':sha(folder/'vk.bin'),'scope':'Stateless cryptographic test fixture, not another client proof'})
    print('WRONG_KEY_CRYPTOGRAPHIC_CONTROL_PASS')

if __name__=='__main__':main()
