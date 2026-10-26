import {runRoot,read,write,objectHash} from './io.mjs';
import {loadExpected,checkEnvelope} from './check_protocol.mjs';
const root=runRoot(),loaded=await loadExpected(root),response=read(root,'public/response.json'),pub=read(root,'public/public_signals.json');
// Only the in-memory control fixture is fresh; real consumed state is untouched.
const fresh={...loaded,already_consumed:false,state:{status:'ISSUED',challenge_sha256:objectHash(loaded.challenge)}};
const tests={valid_envelope_fixture:await checkEnvelope(fresh,response,pub),real_consumed_session_rejects_replay:!await checkEnvelope(loaded,response,pub)};
for(const [name,mutate] of [
 ['client',x=>x.client_id++],['seed',x=>x.seed++],['batch',x=>x.selected_batch_id++],
 ['I',x=>x.I=(BigInt(x.I)+1n).toString()],['I_prime',x=>x.I_prime.context_tag=(BigInt(x.I_prime.context_tag)+1n).toString()],
 ['submitted_gradient',x=>x.g_c_batch[0]+=.01],['challenge_hash',x=>x.challenge_sha256='0'.repeat(64)]
]){const altered=structuredClone(response);mutate(altered);tests['wrong_'+name+'_rejected']=!await checkEnvelope(fresh,altered,pub);}
for(const [name,mutate] of [
 ['round',x=>x.challenge.validation_paper_round=8],['nonce',x=>x.challenge.nonce=(BigInt(x.challenge.nonce)+1n).toString()],
 ['verification_key_record',x=>x.key.verification_key_sha256='0'.repeat(64)]
]){const altered=structuredClone(fresh);mutate(altered);tests['wrong_'+name+'_rejected']=!await checkEnvelope(altered,response,pub);}
const badPub=[...pub];badPub[2]=(BigInt(badPub[2])+1n).toString();tests.changed_public_input_rejected=!await checkEnvelope(fresh,response,badPub);
if(Object.values(tests).some(x=>x!==true))throw Error('Protocol regression');
write(root,'public/protocol_negative_tests.json',{tests,all_passed:true,scope:'Envelope/session checks, not substitutes for native cryptographic negative tests'});
console.log('PROTOCOL_NEGATIVE_TESTS_OK');
