// Envelope checks only. An ACCEPTED verdict ALSO requires native libsnark Verify.
// No dependency on a ground-truth label, PyTorch, captured batch or witness.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {runRoot,read,write,objectHash,fileHash,updateHash} from './io.mjs';
import {serverInputs,requirePins} from './server_inputs.mjs';
import {hashes,modelTag,sessionTag,tag,updateCommitment} from './encoding.mjs';

export async function loadExpected(root){
 const inputs=serverInputs(root),key=read(root,'server/key_record.json');requirePins(inputs,key);
 if(key.backend!=='libsnark/r1cs_gg_ppzksnark/ALT_BN128'||
    await fileHash(path.join(root,'server/verification_key.bin'))!==key.verification_key_sha256||
    await fileHash(path.join(root,'work/server/batch_sgd.arith'))!==key.arith_sha256)
  throw Error('Server circuit/backend/VK pins differ');
 return {...inputs,key,challenge:read(root,'server/challenge.json'),state:read(root,'server/session_state.json'),
  already_consumed:fs.existsSync(path.join(root,'server/challenge_consumed.json'))};
}
export async function checkEnvelope(expected,response,signals){
 try{
  const {c,manifest,key,challenge,state,update}=expected;
  if(expected.already_consumed||state.status!=='ISSUED'||state.challenge_sha256!==objectHash(challenge))return false;
  if(challenge.schema!==c.schema||challenge.seed!==c.seed||challenge.client_id!==c.client_id||
    challenge.reference_paper_round!==6||challenge.validation_paper_round!==7||
    challenge.stage1_case_sha256!==expected.pins.case||challenge.manifest_sha256!==expected.pins.manifest||
    challenge.key_record_sha256!==objectHash(key)||challenge.input_model_sha256!==c.input_model_sha256||
    challenge.submitted_update_sha256!==c.submitted_update_sha256||challenge.candidate_count!==1||challenge.selected_batch_id!==0)return false;
  const nonce=BigInt(challenge.nonce);if(nonce<0n||nonce>=(1n<<128n))return false;
  const {hash}=await hashes();
  const context=hash([modelTag(c.input_model_sha256),sessionTag(c),tag(manifest),0,nonce]).toString();
  const I=manifest.batches[0].batch_commitment,updateI=await updateCommitment(update);
  if(challenge.I!==I||challenge.update_commitment!==updateI||challenge.context_tag!==context)return false;
  if(response.schema!==c.schema||response.seed!==c.seed||response.client_id!==c.client_id||
    response.challenge_sha256!==objectHash(challenge)||response.selected_batch_id!==0||response.I!==I||
    response.I_prime?.update_commitment!==updateI||response.I_prime?.context_tag!==context||
    updateHash(response.g_c_batch)!==c.submitted_update_sha256)return false;
  const required=['1',challenge.nonce,I,updateI,context].map(String);
  return Array.isArray(signals)&&signals.length===5&&signals.every((s,i)=>String(s)===required[i]);
 }catch{return false;}
}
async function main(){
 const root=runRoot(),expected=await loadExpected(root),response=read(root,'public/response.json'),signals=read(root,'public/public_signals.json');
 if(!await checkEnvelope(expected,response,signals))throw Error('ENVELOPE_REJECTED');
 fs.writeFileSync(path.join(root,'server/expected_public_inputs.txt'),signals.join('\n')+'\n');
 write(root,'public/envelope_check.json',{passed:true,cryptographic_verification:false,note:'Native libsnark Verify must still succeed'});
 console.log('ENVELOPE_OK_NOT_A_ZKP_VERDICT');
}
if(process.argv[1]&&path.resolve(process.argv[1]).toLowerCase()===fileURLToPath(import.meta.url).toLowerCase())await main();
