// The public phase-1 file is linked by iden3/snarkjs's README. Pin its BLAKE2b.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root=path.dirname(fileURLToPath(import.meta.url));
const name='powersOfTau28_hez_final_21.ptau';
const expected='9aef0573cef4ded9c4a75f148709056bf989f80dad96876aadeb6f1c6d062391f07a394a9e756d16f7eb233198d5b69407cca44594c763ab4a5b67ae73254678';
const target=path.join(root,'cache',name),part=target+'.part';
fs.mkdirSync(path.dirname(target),{recursive:true});
async function digest(p){const h=crypto.createHash('blake2b512');for await(const c of fs.createReadStream(p))h.update(c);return h.digest('hex');}
if(fs.existsSync(target)){
 if(await digest(target)!==expected)throw Error('Cached ptau hash mismatch');
 console.log('Verified cached public ptau');
}else{
 const url='https://circom.info/'+name;
 const head=await fetch(url,{method:'HEAD',signal:AbortSignal.timeout(30000)});
 if(!head.ok)throw Error('ptau download HTTP '+head.status);
 const length=Number(head.headers.get('content-length'));
 const handle=await fs.promises.open(part,'w');
 const block=8*1024*1024;let next=0,total=0,last=Date.now();
 try {
  await Promise.all(Array.from({length:6},async()=>{
   while(next<length){
    const start=next;next+=block;const end=Math.min(start+block,length)-1;
    let bytes;
    for(let retry=0;retry<5;retry++){
     try{
      const r=await fetch(url,{headers:{Range:`bytes=${start}-${end}`},signal:AbortSignal.timeout(90000)});
      if(r.status!==206)throw Error('Range HTTP '+r.status);
      bytes=Buffer.from(await r.arrayBuffer());
      if(bytes.length!==end-start+1)throw Error('Incomplete range');
      break;
     }catch(e){if(retry===4)throw e;}
    }
    let written=0;while(written<bytes.length){const w=await handle.write(bytes,written,bytes.length-written,start+written);written+=w.bytesWritten;}
    total+=bytes.length;
    if(Date.now()-last>15000){console.log('ptau bytes='+total+'/'+length);last=Date.now();}
   }
  }));
 }finally{await handle.close();}
 if(await digest(part)!==expected)throw Error('Downloaded ptau hash mismatch; refuse to use it');
 fs.renameSync(part,target);
 console.log('Downloaded and BLAKE2b-verified '+total+' bytes');
}
