import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';

export const SOURCE=path.dirname(fileURLToPath(import.meta.url));
export const LEGACY=path.dirname(SOURCE);
export function runRoot(){
 const raw=process.env.FRDETECTER_ZKP_RUN_DIR;
 if(!raw)throw Error('Use run_paper_aligned.py; FRDETECTER_ZKP_RUN_DIR is required');
 const root=path.resolve(raw),base=path.join(LEGACY,'runs'),rel=path.relative(base,root);
 if(!rel||rel.startsWith('..')||path.isAbsolute(rel)||!fs.statSync(root).isDirectory())
  throw Error('Run directory must be an existing dedicated child of stage2_zkp_single_client/runs');
 return root;
}
export const read=(root,p)=>JSON.parse(fs.readFileSync(path.join(root,p),'utf8'));
export function write(root,p,obj){
 const target=path.join(root,p);fs.mkdirSync(path.dirname(target),{recursive:true});
 fs.writeFileSync(target,JSON.stringify(obj,(_,v)=>typeof v==='bigint'?v.toString():v,2)+'\n');
}
export function createOnce(root,p,obj){
 const target=path.join(root,p);fs.mkdirSync(path.dirname(target),{recursive:true});
 fs.writeFileSync(target,JSON.stringify(obj,null,2)+'\n',{flag:'wx'});
}
export function canonical(x){
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 if(x!==null&&typeof x==='object')return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
 return JSON.stringify(x);
}
export const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
export const objectHash=x=>sha(canonical(x));
export async function fileHash(file){
 const h=crypto.createHash('sha256');for await(const block of fs.createReadStream(file))h.update(block);return h.digest('hex');
}
export function tensorHash(values,shape,dtype,width){
 const bytes=Buffer.alloc(values.length*width);
 values.forEach((v,i)=>{if(!Number.isFinite(v))throw Error('Non-finite tensor');width===4?bytes.writeFloatLE(v,4*i):bytes.writeDoubleLE(v,8*i);});
 return crypto.createHash('sha256').update(shape).update(dtype).update(bytes).digest('hex');
}
export function modelHash(model){
 if(model.weights?.length!==10||model.weights.some(r=>r.length!==784)||model.bias?.length!==10)throw Error('Model dimensions');
 return crypto.createHash('sha256').update('linear.weight').update(tensorHash(model.weights.flat(),'(10, 784)','torch.float32',4))
  .update('linear.bias').update(tensorHash(model.bias,'(10,)','torch.float32',4)).digest('hex');
}
export const updateHash=values=>{if(values?.length!==7850)throw Error('Update dimensions');return tensorHash(values,'(7850,)','torch.float64',8);};
export function requireCase(c){
 const p=c.protocol;
 if(c.schema!=='frdetecter-paper-aligned-v2'||!c.suspicious||!(c.cosine_similarity<c.threshold)||
    p?.reference_paper_round!==6||p.validation_paper_round!==7||p.local_steps!==1||p.batch_size!==64||
    p.learning_rate!==0.10||p.optimizer!=='SGD'||p.communication_rounds!==8||p.threshold!==0.1)
  throw Error('Case is not the frozen 6->7, single-minibatch Stage-1 protocol');
}
