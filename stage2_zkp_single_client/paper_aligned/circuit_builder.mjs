// Server KeyGen circuit builder: reads only server/public values, no private batch.
import fs from 'node:fs';
import path from 'node:path';
import {runRoot,LEGACY,write} from './io.mjs';
import {serverInputs} from './server_inputs.mjs';
import {quantize,modelTag,sessionTag,tag} from './encoding.mjs';

const root=runRoot(),{c,model,manifest,pins}=serverInputs(root);
const W=model.weights.map(row=>row.map(quantize)),b=model.bias.map(quantize);
const modelId=modelTag(c.input_model_sha256),session=sessionTag(c),manifestId=tag(manifest);
const constants=`pragma circom 2.1.6;\nfunction weights(){return [${W.map(row=>'['+row.join(',')+']').join(',')}];}\nfunction biases(){return [${b.join(',')}];}\n`;
function balanced(xs){if(xs.length===1)return xs[0];const m=Math.floor(xs.length/2);return '('+balanced(xs.slice(0,m))+'+'+balanced(xs.slice(m))+')';}
const logits=W.map((row,k)=>`ld[n][${k}]=FloorDiv(255,34,8);ld[n][${k}].a<==${balanced([(b[k]*255n).toString(),...row.map((w,j)=>w===0n?'0':`(${w})*pixels[n][${j}]`)])};logits[n][${k}]<==ld[n][${k}].q;`).join('\n');
const gradient=balanced(Array.from({length:64},(_,n)=>`products[k][j][${n}]`));
const bias=balanced(Array.from({length:64},(_,n)=>`residual[${n}][k]`));
const source=`pragma circom 2.1.6;
include "arithmetic.circom";
include "model_constants.circom";
template BatchSGD(){
 var Q=1073741824;
 signal input pixels[64][784];signal input labels[64];signal input submitted[7850];
 signal input salt;signal input nonce;signal input dataCommitment;signal input updateCommitment;signal input contextTag;
 component ctx=Poseidon(5);
 ctx.inputs[0]<==${modelId};ctx.inputs[1]<==${session};ctx.inputs[2]<==${manifestId};ctx.inputs[3]<==0;ctx.inputs[4]<==nonce;
 ctx.out===contextTag;
 component sb=Num2Bits(128);sb.in<==salt;component nb=Num2Bits(128);nb.in<==nonce;
 component px[64][784];
 for(var n=0;n<64;n++)for(var j=0;j<784;j++){px[n][j]=Num2Bits(8);px[n][j].in<==pixels[n][j];}
 component lb[64];component lt[64];component eq[64][10];
 for(var n=0;n<64;n++){
  lb[n]=Num2Bits(4);lb[n].in<==labels[n];lt[n]=LessThan(4);lt[n].in[0]<==labels[n];lt[n].in[1]<==10;lt[n].out===1;
  for(var k=0;k<10;k++){eq[n][k]=IsEqual();eq[n][k].in[0]<==labels[n];eq[n][k].in[1]<==k;}
 }
 signal packedData[1675];
 for(var i=0;i<1675;i++){
  var v=0;for(var j=0;j<30;j++){var t=30*i+j;if(t<50176)v+=pixels[t\\784][t%784]*(1<<(8*j));else if(t<50240)v+=labels[t-50176]*(1<<(8*j));}
  packedData[i]<==v;
 }
 component dc=Commit(1675,1);dc.salt<==salt;
 for(var i=0;i<1675;i++)dc.values[i]<==packedData[i];dc.out===dataCommitment;
 component ranges[7850];signal encoded[7850];
 for(var i=0;i<7850;i++){encoded[i]<==submitted[i]+33554432;ranges[i]=Num2Bits(26);ranges[i].in<==encoded[i];}
 signal packedUpdate[982];
 for(var i=0;i<982;i++){var v=0;for(var j=0;j<8;j++){var t=8*i+j;if(t<7850)v+=encoded[t]*(1<<(26*j));}packedUpdate[i]<==v;}
 component uc=Commit(982,2);uc.salt<==0;
 for(var i=0;i<982;i++)uc.values[i]<==packedUpdate[i];uc.out===updateCommitment;
 signal logits[64][10];component ld[64][10];signal maximum[64][10];component cmp[64][9];
 component ex[64][10];signal total[64];component pr[64][10];signal residual[64][10];
 for(var n=0;n<64;n++){
  ${logits}
  maximum[n][0]<==logits[n][0];
  for(var k=1;k<10;k++){
   cmp[n][k-1]=LessThan(35);cmp[n][k-1].in[0]<==maximum[n][k-1]+17179869184;cmp[n][k-1].in[1]<==logits[n][k]+17179869184;
   maximum[n][k]<==maximum[n][k-1]+cmp[n][k-1].out*(logits[n][k]-maximum[n][k-1]);
  }
  var sum=0;for(var k=0;k<10;k++){ex[n][k]=ExpNegative();ex[n][k].x<==logits[n][k]-maximum[n][9];sum+=ex[n][k].out;}
  total[n]<==sum;
  for(var k=0;k<10;k++){pr[n][k]=Probability();pr[n][k].e<==ex[n][k].out;pr[n][k].total<==total[n];residual[n][k]<==pr[n][k].p-Q*eq[n][k].out;}
 }
 signal products[10][784][64];signal shifted[7850];component eb[7850];
 for(var k=0;k<10;k++){
  for(var j=0;j<784;j++){
   var i=784*k+j;for(var n=0;n<64;n++)products[k][j][n]<==residual[n][k]*pixels[n][j];
   shifted[i]<==${gradient}-submitted[i]*163200+1073741824;eb[i]=Num2Bits(31);eb[i].in<==shifted[i];
  }
  var i=7840+k;shifted[i]<==${bias}-submitted[i]*640+4194304;eb[i]=Num2Bits(23);eb[i].in<==shifted[i];
 }
}
component main {public [nonce,dataCommitment,updateCommitment,contextTag]}=BatchSGD();
`;
fs.mkdirSync(path.join(root,'work'),{recursive:true});
fs.copyFileSync(path.join(LEGACY,'circuits/arithmetic.circom'),path.join(root,'work/arithmetic.circom'));
// Keep relative include resolution portable without Windows drive-letter paths
// inside Circom source. This copies the already-installed pinned library only.
fs.cpSync(path.join(LEGACY,'node_modules/circomlib/circuits'),path.join(root,'work/circomlib'),{recursive:true,errorOnExist:true,force:false});
const arithmetic=fs.readFileSync(path.join(root,'work/arithmetic.circom'),'utf8')
 .replaceAll('../node_modules/circomlib/circuits/','circomlib/');
fs.writeFileSync(path.join(root,'work/arithmetic.circom'),arithmetic);
fs.writeFileSync(path.join(root,'work/model_constants.circom'),constants);
fs.writeFileSync(path.join(root,'work/batch_sgd.circom'),source);
write(root,'server/circuit_spec.json',{schema:c.schema,input_pins:pins,public_signal_order:['nonce','dataCommitment','updateCommitment','contextTag'],
 proof_scope:'Fixed-point one-batch SGD relation with frozen tolerance against the actual Stage-1 update; not IEEE-754 equivalence',
 original_backend_reproduced:false,raw_gradient_convention:'g_c = theta_base - theta_local = lr * loss_gradient for one SGD step (float rounding applies)',
 weights_are_checkpoint_specific_constants:true,error_budget_units:'10738',fixed_point_scale:'1073741824'});
console.log(JSON.stringify({circuit_built:true,private_data_read:false,keygen_precedes_stage2_compute:true}));
