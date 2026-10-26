// Client registration followed by a trusted-local server acceptance boundary.
// Must finish BEFORE the server chooses the challenge/nonce.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {runRoot,read,write,createOnce,sha,objectHash,requireCase} from './io.mjs';
import {hashes,batchValues} from './encoding.mjs';

const root=runRoot(),c=read(root,'public/stage1_case.json'),data=read(root,'client_private/captured_batch.json');
requireCase(c);
if(fs.existsSync(path.join(root,'server/challenge.json')))throw Error('Registration cannot change after challenge');
const capturedHash=sha(JSON.stringify({pixels:data.pixels,labels:data.labels}));
if(capturedHash!==c.pretraining_batch_sha256||capturedHash!==data.pretraining_batch_sha256)
 throw Error('Trusted capture hash differs from Stage-1 pretraining capture');
const salt=BigInt('0x'+crypto.randomBytes(16).toString('hex'));
const {commit}=await hashes();
const I=commit(batchValues(data),1,salt).toString();
const manifest={schema:c.schema,seed:c.seed,client_id:c.client_id,input_model_sha256:c.input_model_sha256,
 validation_paper_round:7,eligible_batch_count:1,
 batches:[{batch_id:0,sample_count:64,batch_commitment:I}],
 authenticity:'Trusted local capture of the actual Stage-1 validation batch; not remote dataset provenance'};
createOnce(root,'server/batch_manifest.json',manifest);
write(root,'public/batch_manifest.json',manifest);
write(root,'client_private/registration.json',{salt:salt.toString(),batch_id:0,I,manifest_sha256:objectHash(manifest)});
console.log(JSON.stringify({registered:true,candidate_count:1,selection_degenerate:true}));
