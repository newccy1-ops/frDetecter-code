// Independent server Verify: no imports of torch, datasets, exporter or private witness.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {performance} from 'node:perf_hooks';
import {groth16} from 'snarkjs';
import {buildBn128} from 'ffjavascript';
import {runRoot,read,write,createOnce,objectHash,fileHash,updateHash} from './io.mjs';
import {serverInputs,requirePins} from './server_inputs.mjs';
import {hashes,modelTag,sessionTag,tag,updateCommitment} from './encoding.mjs';

export async function loadServerExpectation(root){
 const inputs=serverInputs(root),key=read(root,'server/key_record.json');requirePins(inputs,key);
 const vkPath=path.join(root,'server/verification_key.json');
 if(await fileHash(vkPath)!==key.verification_key_sha256)throw Error('Server pinned verification key was changed');
 return {...inputs,key,vkey:read(root,'server/verification_key.json'),
         challenge:read(root,'server/challenge.json'),state:read(root,'server/session_state.json'),
         already_consumed:fs.existsSync(path.join(root,'server/challenge_consumed.json'))};
}

export async function verifyBundle(expected,response,publicSignals,proof){
 try{
  const {c,manifest,key,challenge,state,update}=expected;
  if(expected.already_consumed||state.status!=='ISSUED'||state.challenge_sha256!==objectHash(challenge))return false;
  if(challenge.schema!==c.schema||challenge.seed!==c.seed||challenge.client_id!==c.client_id||
     challenge.reference_paper_round!==6||challenge.validation_paper_round!==7||
     challenge.stage1_case_sha256!==expected.pins.case||challenge.manifest_sha256!==expected.pins.manifest||
     challenge.key_record_sha256!==objectHash(key)||challenge.input_model_sha256!==c.input_model_sha256||
     challenge.submitted_update_sha256!==c.submitted_update_sha256||challenge.candidate_count!==1||challenge.selected_batch_id!==0)
   return false;
  const nonce=BigInt(challenge.nonce);
  if(nonce<0n||nonce>=(1n<<128n))return false;
  const {hash}=await hashes();
  const context=hash([modelTag(c.input_model_sha256),sessionTag(c),tag(manifest),challenge.selected_batch_id,nonce]).toString();
  const I=manifest.batches[0].batch_commitment,updateI=await updateCommitment(update);
  if(challenge.I!==I||challenge.update_commitment!==updateI||challenge.context_tag!==context)return false;
  if(response.schema!==c.schema||response.seed!==c.seed||response.client_id!==c.client_id||
     response.challenge_sha256!==objectHash(challenge)||response.selected_batch_id!==challenge.selected_batch_id||
     response.I!==I||response.I_prime?.update_commitment!==updateI||response.I_prime?.context_tag!==context||
     updateHash(response.g_c_batch)!==c.submitted_update_sha256)return false;
  const required=[challenge.nonce,I,updateI,context].map(String);
  if(!Array.isArray(publicSignals)||publicSignals.length!==4||publicSignals.some((x,i)=>String(x)!==required[i]))return false;
  return await groth16.verify(expected.vkey,publicSignals,proof);
 }catch{return false;}
}

async function main(){
 const root=runRoot(),expected=await loadServerExpectation(root),started=performance.now();
 const curve=await buildBn128(true);globalThis.curve_bn128=curve;
 try{
  const proof=read(root,'public/proof.json'),pub=read(root,'public/public_signals.json'),response=read(root,'public/response.json');
  let ok=await verifyBundle(expected,response,pub,proof);
  if(ok){
   try{
    // wx is atomic: two verifiers cannot successfully consume the same challenge.
    createOnce(root,'server/challenge_consumed.json',{challenge_sha256:objectHash(expected.challenge),accepted:true});
   }catch(error){if(error.code==='EEXIST')ok=false;else throw error;}
  }
  if(ok)write(root,'server/session_state.json',{status:'CONSUMED',challenge_sha256:objectHash(expected.challenge)});
  const result={status:ok?'ACCEPTED':'REJECTED',verify_output:ok?1:0,cryptographic_verification:ok,
   selected_client_prediction:ok?'benign':'free_rider',verification_seconds:(performance.now()-started)/1000,
   private_witness_accessed:false,ground_truth_accessed:false,client_id:expected.c.client_id,
   executed_rounds:{reference:6,validation:7},scope:'One selected client; no global two-stage metric claimed'};
  result.verified_file_sha256={};
  for(const name of ['public/proof.json','public/public_signals.json','public/response.json','server/verification_key.json','server/challenge.json'])
   result.verified_file_sha256[name]=await fileHash(path.join(root,name));
  write(root,'public/verification.json',result);console.log(JSON.stringify(result));process.exitCode=ok?0:1;
 }finally{await curve.terminate();}
}
if(process.argv[1]&&path.resolve(process.argv[1]).toLowerCase()===fileURLToPath(import.meta.url).toLowerCase())await main();
