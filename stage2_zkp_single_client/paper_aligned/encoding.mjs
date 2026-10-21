import {buildPoseidon} from 'circomlibjs';
import {objectHash} from './io.mjs';
export const P=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const Q=1n<<30n;
export const ERROR_UNITS=10738n;
export const field=x=>((BigInt(x)%P)+P)%P;
export const quantize=x=>BigInt(Math.round(x*Number(Q)));
export const floorDiv=(a,b)=>a>=0n?a/b:-((-a+b-1n)/b);
export function pack(items,width,count){
 const result=[];for(let i=0;i<items.length;i+=count){let v=0n;for(let j=0;j<count&&i+j<items.length;j++)v+=BigInt(items[i+j])<<BigInt(width*j);result.push(v);}return result;
}
let engine;
export async function hashes(){
 engine??=await buildPoseidon();
 const hash=xs=>BigInt(engine.F.toString(engine(xs.map(field))));
 const commit=(values,domain,salt=0n)=>{let st=hash([domain,values.length,salt]);for(let i=0;i<values.length;i+=15)st=hash([st,...Array.from({length:15},(_,j)=>values[i+j]??0n)]);return st;};
 return {hash,commit};
}
export const tag=x=>BigInt('0x'+objectHash(x))%P;
export const modelTag=sha256=>BigInt('0x'+sha256)%P;
export const sessionTag=c=>tag({schema:c.schema,seed:c.seed,client_id:c.client_id,reference:6,validation:7,batch:64,steps:1,lr:'1/10'});
export function encodedUpdate(update){
 const q=update.map(quantize);
 if(q.length!==7850||q.some(x=>x<-(1n<<25n)||x>=(1n<<25n)))throw Error('Update outside frozen domain [-1/32,1/32)');
 return {q,packed:pack(q.map(x=>x+(1n<<25n)),26,8)};
}
export function batchValues(data){
 if(data.pixels?.length!==64||data.pixels.some(row=>row.length!==784||row.some(x=>!Number.isInteger(x)||x<0||x>255))||
    data.labels?.length!==64||data.labels.some(x=>!Number.isInteger(x)||x<0||x>9))throw Error('Invalid private MNIST batch');
 return pack(data.pixels.flat().concat(data.labels),8,30);
}
export async function updateCommitment(update){const {commit}=await hashes();return commit(encodedUpdate(update).packed,2).toString();}
