// Client Compute: reconstruct the specified fixed-point forward/backward pass.
// No training configuration, Stage-1 update or tolerance is tuned here.
import {runRoot,read,write,requireCase,modelHash,updateHash,objectHash,sha} from './io.mjs';
import {Q,ERROR_UNITS,hashes,quantize,floorDiv,field,encodedUpdate,batchValues,modelTag,sessionTag,tag} from './encoding.mjs';

const root=runRoot(),c=read(root,'public/stage1_case.json'),model=read(root,'public/model.json');requireCase(c);
const challenge=read(root,'public/challenge.json'),manifest=read(root,'public/batch_manifest.json');
const data=read(root,'client_private/captured_batch.json'),registration=read(root,'client_private/registration.json');
const submitted=read(root,'client_private/submitted_update.json');
if(modelHash(model)!==c.input_model_sha256||updateHash(submitted)!==c.submitted_update_sha256)throw Error('Client model/update binding');
if(objectHash(c)!==challenge.stage1_case_sha256||objectHash(manifest)!==challenge.manifest_sha256||registration.manifest_sha256!==challenge.manifest_sha256||
 challenge.selected_batch_id!==registration.batch_id||challenge.seed!==c.seed||challenge.client_id!==c.client_id||
 challenge.reference_paper_round!==6||challenge.validation_paper_round!==7||challenge.input_model_sha256!==c.input_model_sha256)
 throw Error('Server challenge targets a different case/model/batch');
if(sha(JSON.stringify({pixels:data.pixels,labels:data.labels}))!==c.pretraining_batch_sha256)throw Error('Capture differs from actual batch');
const {hash,commit}=await hashes(),salt=BigInt(registration.salt),I=commit(batchValues(data),1,salt).toString();
const encoded=encodedUpdate(submitted),updateI=commit(encoded.packed,2).toString();
const context=hash([modelTag(c.input_model_sha256),sessionTag(c),tag(manifest),challenge.selected_batch_id,BigInt(challenge.nonce)]).toString();
if(I!==challenge.I||I!==registration.I||context!==challenge.context_tag||updateI!==challenge.update_commitment)throw Error('Commitment/challenge mismatch');
const W=model.weights.map(row=>row.map(quantize)),b=model.bias.map(quantize);
const coefficients=[1073741824n,1073741824n,536870912n,178956971n,44739243n,8947849n,1491308n];
function expFixed(x){const t=floorDiv(x,32n);let z=coefficients[6];for(let k=5;k>=0;k--)z=coefficients[k]+floorDiv(z*t,Q);for(let k=0;k<5;k++)z=floorDiv(z*z,Q);return z;}
const residual=[];
for(let n=0;n<64;n++){
 const logits=W.map((row,k)=>floorDiv(row.reduce((sum,w,j)=>sum+w*BigInt(data.pixels[n][j]),b[k]*255n),255n));
 if(logits.some(x=>x< -16n*Q||x>=16n*Q))throw Error('Outside frozen logit domain');
 const max=logits.reduce((a,b)=>a>b?a:b),e=logits.map(x=>expFixed(x-max)),total=e.reduce((a,b)=>a+b,0n);
 residual.push(e.map((v,k)=>v*Q/total-(data.labels[n]===k?Q:0n)));
}
const numerators=[],denominators=[];
for(let k=0;k<10;k++)for(let j=0;j<784;j++){
 numerators.push(residual.reduce((sum,r,n)=>sum+r[k]*BigInt(data.pixels[n][j]),0n));denominators.push(163200n);
}
for(let k=0;k<10;k++){numerators.push(residual.reduce((sum,r)=>sum+r[k],0n));denominators.push(640n);}
let maxError=0;
for(let i=0;i<7850;i++){
 const residualInteger=numerators[i]-encoded.q[i]*denominators[i];
 const bound=i<7840?(1n<<30n):(1n<<22n);
 if(residualInteger< -bound||residualInteger>=bound)throw Error('Frozen circuit tolerance exceeded at '+i);
 const error=Math.abs(Number(floorDiv(numerators[i],denominators[i])-encoded.q[i])/Number(Q));
 if(error>Number(ERROR_UNITS)/Number(Q))throw Error('Nominal frozen tolerance exceeded');maxError=Math.max(maxError,error);
}
write(root,'client_private/circuit_input.json',{pixels:data.pixels,labels:data.labels,submitted:encoded.q.map(field),salt,
 nonce:challenge.nonce,dataCommitment:I,updateCommitment:updateI,contextTag:context});
write(root,'client_private/compute_audit.json',{computed:true,num_samples:64,num_update_coordinates:7850,max_coordinate_error:maxError,
 nominal_error_budget:Number(ERROR_UNITS)/Number(Q),fixed_point_scale:Q,
 scope:'Fixed-point approximation checked against the unmodified Stage-1 float upload; not bit-exact floating point'});
write(root,'public/compute_result.json',{schema:c.schema,challenge_sha256:objectHash(challenge),seed:c.seed,client_id:c.client_id,
 selected_batch_id:challenge.selected_batch_id,g_c_batch:submitted,I,
 I_prime:{update_commitment:updateI,context_tag:context},
 I_prime_mapping:'DEMO_ASSUMPTION: auxiliary commitment is the update commitment plus session context; manuscript does not define its encoding',
 gradient_convention:challenge.gradient_convention});
console.log(JSON.stringify({Compute:true,coordinates:7850,I,sample_count:64}));
