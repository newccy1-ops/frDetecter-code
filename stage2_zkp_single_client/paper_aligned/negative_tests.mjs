// Future-run regression tests. This file has NOT been executed by the edit task.
import path from 'node:path';
import {buildBn128} from 'ffjavascript';
import {wtns} from 'snarkjs';
import {runRoot,read,write,objectHash} from './io.mjs';
import {P,field,hashes,pack} from './encoding.mjs';
import {loadServerExpectation,verifyBundle} from './verify.mjs';

const root=runRoot(),loaded=await loadServerExpectation(root);
const response=read(root,'public/response.json'),pub=read(root,'public/public_signals.json'),proof=read(root,'public/proof.json');
const curve=await buildBn128(true);globalThis.curve_bn128=curve;
try{
 // Positive/control tests use an in-memory PRE-consumption server state.
 // The real on-disk consumed state is not reset or mutated.
 const fresh={...loaded,already_consumed:false,state:{status:'ISSUED',challenge_sha256:objectHash(loaded.challenge)}};
 const tests={valid_proof_fixture_accepted:await verifyBundle(fresh,response,pub,proof),
              real_consumed_session_rejects_replay:!await verifyBundle(loaded,response,pub,proof)};
 for(const [name,mutate] of [
  ['client',x=>x.client_id++],['seed',x=>x.seed++],['batch',x=>x.selected_batch_id++],
  ['I',x=>x.I=(BigInt(x.I)+1n).toString()],
  ['I_prime',x=>x.I_prime.context_tag=(BigInt(x.I_prime.context_tag)+1n).toString()],
  ['submitted_gradient',x=>x.g_c_batch[0]+=.01],['challenge_hash',x=>x.challenge_sha256='0'.repeat(64)]
 ]){const altered=structuredClone(response);mutate(altered);tests['wrong_'+name+'_rejected']=!await verifyBundle(fresh,altered,pub,proof);}
 const stale=structuredClone(fresh);stale.challenge.validation_paper_round=8;
 tests.wrong_round_rejected=!await verifyBundle(stale,response,pub,proof);
 const other=structuredClone(fresh);other.challenge.nonce=(BigInt(other.challenge.nonce)+1n).toString();
 tests.wrong_nonce_rejected=!await verifyBundle(other,response,pub,proof);
 const alteredProof=structuredClone(proof);alteredProof.pi_a[0]=(BigInt(alteredProof.pi_a[0])+1n).toString();
 tests.tampered_proof_rejected=!await verifyBundle(fresh,response,pub,alteredProof);
 tests.missing_proof_rejected=!await verifyBundle(fresh,response,pub,{});
 const wrongKey=structuredClone(fresh);wrongKey.vkey.IC[0][0]=(BigInt(wrongKey.vkey.IC[0][0])+1n).toString();
 tests.wrong_verification_key_rejected=!await verifyBundle(wrongKey,response,pub,proof);
 const {commit}=await hashes();
 for(const coordinate of [0,2500,7849]){
  const input=read(root,'client_private/circuit_input.json');
  input.submitted[coordinate]=field(BigInt(input.submitted[coordinate])+10737418n).toString();
  const signed=input.submitted.map(x=>BigInt(x)>P/2n?BigInt(x)-P:BigInt(x));
  input.updateCommitment=commit(pack(signed.map(x=>x+(1n<<25n)),26,8),2).toString();
  let rejected=false;
  try{await wtns.calculate(input,path.join(root,'work/batch_sgd_js/batch_sgd.wasm'),path.join(root,`client_private/invalid_${coordinate}.wtns`));}
  catch(error){if(!String(error.message).includes('Assert Failed')||!String(error.message).includes('Num2Bits'))throw error;rejected=true;}
  tests[`recommitted_invalid_coordinate_${coordinate}_fails_training_constraints`]=rejected;
 }
 if(Object.values(tests).some(x=>x!==true))throw Error('Protocol/cryptographic regression failure');
 write(root,'public/negative_tests.json',{tests,all_passed:true,fixture_scope:'Only stateless controls use a fresh-state fixture; real consumed-session replay is also checked'});
 console.log('PASS protocol/cryptographic tests');
}finally{await curve.terminate();}
