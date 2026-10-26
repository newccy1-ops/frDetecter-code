// Server-only compiler inputs: public checkpoint and frozen metadata, no batch.
import fs from 'node:fs';
import path from 'node:path';
import {runRoot,write,SOURCE} from './io.mjs';
import {serverInputs} from './server_inputs.mjs';
import {quantize,modelTag,sessionTag,tag} from './encoding.mjs';
const root=runRoot(),inputs=serverInputs(root),{c,model,manifest}=inputs;
const spec={schema:c.schema,input_pins:inputs.pins,model_tag:modelTag(c.input_model_sha256),
 session_tag:sessionTag(c),manifest_tag:tag(manifest),weights_q:model.weights.map(r=>r.map(quantize)),bias_q:model.bias.map(quantize),
 public_signal_order:['ONE','nonce','dataCommitment','updateCommitment','contextTag'],
 compiler:'Java/jsnark',backend:'libsnark/r1cs_gg_ppzksnark/ALT_BN128',
 scope:'Same bounded fixed-point single-batch relation; not IEEE-754 or data provenance',private_batch_read:false};
write(root,'server/circuit_spec.json',spec);write(root,'public/circuit_spec.json',spec);
fs.mkdirSync(path.join(root,'work/server'),{recursive:true});
fs.writeFileSync(path.join(root,'work/server/dummy.in'),'0 1\n');
const constants=path.join(SOURCE,'../stage2_zkp_single_client/node_modules/circomlibjs/src/poseidon_constants_opt.json');
fs.copyFileSync(constants,path.join(root,'work/poseidon_constants_opt.json'));
console.log('SERVER_CIRCUIT_INPUTS_OK private_batch_read=false');
