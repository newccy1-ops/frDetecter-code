// Server-side KeyGen. Never reads client_private/.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {zKey} from 'snarkjs';
import {buildBn128} from 'ffjavascript';
import {runRoot,LEGACY,read,write,fileHash} from './io.mjs';
import {serverInputs,requirePins} from './server_inputs.mjs';

const root=runRoot(),action=process.argv[2];
const spec=read(root,'server/circuit_spec.json');requirePins(serverInputs(root),spec);
const work=path.join(root,'work'),binary=path.join(LEGACY,'cache/circom-2.2.3.exe');
const logger={debug:console.log,info:console.log,warn:console.warn,error:console.error};
function child(cmd,args,cwd=root){const r=spawnSync(cmd,args,{cwd,stdio:'inherit'});if(r.error)throw r.error;if(r.status!==0)throw Error('Subprocess failed: '+cmd);}
if(action==='compile'){
 if(process.platform==='win32'){
  if(!fs.existsSync(binary))child(process.env.FRDETECTER_PYTHON||'python',[path.join(LEGACY,'fetch_compiler.py')],LEGACY);
  if(await fileHash(binary)!=='e43f132ee6f0aa79b705beceb59c2a7e6a54d7bdeab917ca34e9fc1951d185e1')throw Error('Compiler pin mismatch');
  child(binary,[path.join(work,'batch_sgd.circom'),'--r1cs','--wasm','--sym','--O2','-o',work,'-l',work]);
 }else{
  const require=createRequire(import.meta.url);
  child(process.execPath,[require.resolve('circom2/cli.js'),path.join(work,'batch_sgd.circom'),'--r1cs','--wasm','--sym','--O2','-o',work,'-l',work]);
 }
}else{
 const cpus=os.cpus;let curve;
 try{os.cpus=()=>cpus().slice(0,4);curve=await buildBn128(false);}finally{os.cpus=cpus;}
 globalThis.curve_bn128=curve;
 try{
  if(action==='setup'){
   const ptau=path.join(LEGACY,'cache/powersOfTau28_hez_final_21.ptau');
   // Recheck even if a caller bypasses the orchestrator's CRS-check phase.
   const h=crypto.createHash('blake2b512');for await(const block of fs.createReadStream(ptau))h.update(block);
   if(h.digest('hex')!=='9aef0573cef4ded9c4a75f148709056bf989f80dad96876aadeb6f1c6d062391f07a394a9e756d16f7eb233198d5b69407cca44594c763ab4a5b67ae73254678')
    throw Error('Pinned public CRS checksum mismatch');
   // snarkjs must fail if the new circuit exceeds this pinned CRS; never change
   // arithmetic or budgets to make it fit. No larger unpinned CRS is accepted.
   const ok=await zKey.newZKey(path.join(work,'batch_sgd.r1cs'),ptau,path.join(root,'server/initial.zkey'),logger);
   if(ok===-1)throw Error('KeyGen/CRS capacity failure');
  }else if(action==='contribute'){
   const final=path.join(root,'server/final.zkey');
   await zKey.contribute(path.join(root,'server/initial.zkey'),final,'paper-aligned local demo',crypto.randomBytes(64).toString('hex'),logger);
   const vk=await zKey.exportVerificationKey(final,logger);
   write(root,'server/verification_key.json',vk);
   fs.copyFileSync(final,path.join(root,'public/evaluation_key.zkey'));
   const record={schema:spec.schema,input_pins:spec.input_pins,
    verification_key_sha256:await fileHash(path.join(root,'server/verification_key.json')),
    evaluation_key_sha256:await fileHash(path.join(root,'public/evaluation_key.zkey')),
    circuit_sha256:await fileHash(path.join(work,'batch_sgd.r1cs')),
    wasm_sha256:await fileHash(path.join(work,'batch_sgd_js/batch_sgd.wasm')),
    setup_scope:'Public Hermez phase 1 plus one local phase-2 contribution; not an independently audited MPC ceremony'};
   write(root,'server/key_record.json',record);
   write(root,'public/key_record.json',record);
  }else throw Error('Usage: keygen.mjs compile|setup|contribute');
 }finally{await curve.terminate();}
}
console.log('PASS KeyGen phase '+action);
