import {runRoot,read,write} from './io.mjs';
import {P,Q,field,hashes,pack} from './encoding.mjs';
const root=runRoot(),{commit}=await hashes();
for(const coordinate of [0,2500,7849]){
 const input=read(root,'client_private/circuit_input.json');
 input.submitted[coordinate]=field(BigInt(input.submitted[coordinate])+10737418n).toString();
 const signed=input.submitted.map(x=>BigInt(x)>P/2n?BigInt(x)-P:BigInt(x));
 input.updateCommitment=commit(pack(signed.map(x=>x+(1n<<25n)),26,8),2).toString();
 write(root,`client_private/invalid_${coordinate}.json`,input);
}
console.log('NEGATIVE_INPUTS_RECOMMITTED_NOT_JUST_BAD_HASHES');
