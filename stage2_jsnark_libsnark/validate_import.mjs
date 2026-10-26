// Check the original tensor/batch commitments, not just copied JSON bytes.
import {runRoot,read,write,requireCase,modelHash,updateHash,sha,canonical,fileHash} from './io.mjs';
import {batchValues} from './encoding.mjs';
import path from 'node:path';
const root=runRoot(),audit=read(root,'stage1_import_audit.json');
const c=read(root,'server/stage1_case.json');requireCase(c);
if(c.seed!==audit.seed||c.client_id!==audit.client_id||audit.stage1_replayed!==false||audit.old_cryptographic_artifacts_imported!==false)throw Error('Import identity/scope mismatch');
for(const [name,expected] of Object.entries(audit.imported_payload_sha256)){
 if(await fileHash(path.join(root,name))!==expected||await fileHash(path.join(audit.source_run,name))!==expected)throw Error('Source/import byte hash mismatch');
}
if(canonical(c)!==canonical(read(root,'public/stage1_case.json')))throw Error('Case copies differ');
for(const name of ['server/model.json','public/model.json'])if(modelHash(read(root,name))!==c.input_model_sha256)throw Error('Original model hash mismatch');
for(const name of ['server/submitted_update.json','client_private/submitted_update.json'])if(updateHash(read(root,name))!==c.submitted_update_sha256)throw Error('Original submitted update hash mismatch');
const batch=read(root,'client_private/captured_batch.json');batchValues(batch);
if(sha(JSON.stringify({pixels:batch.pixels,labels:batch.labels}))!==c.pretraining_batch_sha256||batch.pretraining_batch_sha256!==c.pretraining_batch_sha256)throw Error('Original batch hash mismatch');
write(root,'stage1_import_validation.json',{status:'PASS',stage1_replayed:false,original_model_update_batch_hashes_checked:true,imported_payload_bytes_checked:true});
console.log('IMPORTED_STAGE1_PAYLOADS_VALIDATED; no training replay; fresh Stage-2 keys/challenge/proof required');
