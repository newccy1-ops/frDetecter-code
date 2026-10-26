// Server chooses the batch and nonce AFTER registration and KeyGen are frozen.
import crypto from 'node:crypto';
import path from 'node:path';
import {runRoot,read,write,createOnce,objectHash,fileHash} from './io.mjs';
import {serverInputs,requirePins} from './server_inputs.mjs';
import {hashes,modelTag,sessionTag,tag,updateCommitment} from './encoding.mjs';

const root=runRoot(),inputs=serverInputs(root),key=read(root,'server/key_record.json');requirePins(inputs,key);
if(await fileHash(path.join(root,'server/verification_key.bin'))!==key.verification_key_sha256)throw Error('Pinned VK changed');
const {c,manifest}=inputs;
const selected=manifest.batches[crypto.randomInt(manifest.batches.length)];
const nonce=BigInt('0x'+crypto.randomBytes(16).toString('hex'));
const {hash}=await hashes();
const context=hash([modelTag(c.input_model_sha256),sessionTag(c),tag(manifest),selected.batch_id,nonce]).toString();
const challenge={schema:c.schema,seed:c.seed,client_id:c.client_id,reference_paper_round:6,validation_paper_round:7,
 stage1_case_sha256:inputs.pins.case,manifest_sha256:inputs.pins.manifest,key_record_sha256:objectHash(key),
 input_model_sha256:c.input_model_sha256,submitted_update_sha256:c.submitted_update_sha256,
 selected_batch_id:selected.batch_id,candidate_count:manifest.batches.length,singleton_selection:manifest.batches.length===1,
 I:selected.batch_commitment,update_commitment:await updateCommitment(inputs.update),nonce:nonce.toString(),context_tag:context,
 gradient_convention:'g_c = theta_base - theta_local; scaled loss gradient at learning rate 0.10',
 selection_rule:'DEMO_ASSUMPTION: uniform CSPRNG selection over the pre-registered ACTUALLY EXECUTED validation iterations',
 freshness_scope:'Single-use server session binding; not proof of wall-clock execution or no witness reuse'};
createOnce(root,'server/challenge.json',challenge);
write(root,'public/challenge.json',challenge);
createOnce(root,'server/session_state.json',{status:'ISSUED',challenge_sha256:objectHash(challenge)});
console.log(JSON.stringify({issued:true,selected_batch_id:selected.batch_id,candidate_count:manifest.batches.length,nonce_source:'server CSPRNG'}));
