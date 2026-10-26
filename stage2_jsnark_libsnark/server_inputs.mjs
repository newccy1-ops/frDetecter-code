// Server-owned inputs, never supplied by the proof response.
import {read,requireCase,modelHash,updateHash,objectHash} from './io.mjs';

export function serverInputs(root){
 const c=read(root,'server/stage1_case.json');requireCase(c);
 const model=read(root,'server/model.json'),update=read(root,'server/submitted_update.json'),manifest=read(root,'server/batch_manifest.json');
 if(modelHash(model)!==c.input_model_sha256||updateHash(update)!==c.submitted_update_sha256)
  throw Error('Server snapshot/update hash mismatch');
 if(manifest.schema!==c.schema||manifest.seed!==c.seed||manifest.client_id!==c.client_id||
    manifest.input_model_sha256!==c.input_model_sha256||manifest.validation_paper_round!==7||
    manifest.eligible_batch_count!==1||manifest.batches?.length!==1||manifest.batches[0].batch_id!==0||manifest.batches[0].sample_count!==64)
  throw Error('Batch manifest is not the single executed validation iteration');
 return {c,model,update,manifest,pins:{case:objectHash(c),model:objectHash(model),update:objectHash(update),manifest:objectHash(manifest)}};
}
export function requirePins(inputs,record){
 if(objectHash(inputs.pins)!==objectHash(record.input_pins))throw Error('Server inputs changed after KeyGen');
}
