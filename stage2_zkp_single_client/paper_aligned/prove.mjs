// Client Prove using the evaluation key issued by server KeyGen.
import path from 'node:path';
import os from 'node:os';
import {performance} from 'node:perf_hooks';
import {groth16,wtns} from 'snarkjs';
import {buildBn128} from 'ffjavascript';
import {runRoot,read,write,fileHash,objectHash} from './io.mjs';

const root=runRoot(),action=process.argv[2],started=performance.now();
const challenge=read(root,'public/challenge.json'),record=read(root,'public/key_record.json');
if(objectHash(record)!==challenge.key_record_sha256)throw Error('Key package differs from server challenge');
const wasm=path.join(root,'work/batch_sgd_js/batch_sgd.wasm'),circuit=path.join(root,'work/batch_sgd.r1cs');
const ek=path.join(root,'public/evaluation_key.zkey');
if(await fileHash(wasm)!==record.wasm_sha256||await fileHash(circuit)!==record.circuit_sha256||await fileHash(ek)!==record.evaluation_key_sha256)
 throw Error('Client circuit/evaluation-key package checksum mismatch');
const workers=action==='prove'?4:1,cpus=os.cpus;let curve;
try{os.cpus=()=>cpus().slice(0,workers);curve=await buildBn128(workers===1);}finally{os.cpus=cpus;}
globalThis.curve_bn128=curve;
const logger={debug:console.log,info:console.log,warn:console.warn,error:console.error};
try{
 const witness=path.join(root,'client_private/witness.wtns');
 if(action==='witness'){
  await wtns.calculate(read(root,'client_private/circuit_input.json'),wasm,witness);
 }else if(action==='check'){
  if(!await wtns.check(circuit,witness,logger))throw Error('Training relation does not satisfy circuit');
 }else if(action==='prove'){
  const response=read(root,'public/compute_result.json');
  if(response.challenge_sha256!==objectHash(challenge))throw Error('Compute result from a different challenge');
  const {proof,publicSignals}=await groth16.prove(ek,witness,logger,{singleThread:false});
  write(root,'public/proof.json',proof);write(root,'public/public_signals.json',publicSignals);
  write(root,'public/response.json',response);
 }else throw Error('Usage: prove.mjs witness|check|prove');
 write(root,`logs/timing_${action}.json`,{seconds:(performance.now()-started)/1000,peak_rss_bytes:process.resourceUsage().maxRSS*1024,curve_workers:workers});
 console.log('PASS '+action);
}finally{await curve.terminate();}
