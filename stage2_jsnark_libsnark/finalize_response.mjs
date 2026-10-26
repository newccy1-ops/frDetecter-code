import fs from 'node:fs';
import path from 'node:path';
import {runRoot,read,write} from './io.mjs';
const root=runRoot(),challenge=read(root,'public/challenge.json');
write(root,'public/response.json',read(root,'public/compute_result.json'));
const pub=['1',challenge.nonce,challenge.I,challenge.update_commitment,challenge.context_tag].map(String);
write(root,'public/public_signals.json',pub);
fs.writeFileSync(path.join(root,'public/primary_inputs.txt'),pub.join('\n')+'\n');
console.log('RESPONSE_BOUND_TO_ORIGINAL_STAGE1_UPLOAD');
