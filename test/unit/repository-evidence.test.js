import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto,createHash} from 'node:crypto';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {detectFormat} from '../../src/detect.js';
import {verifyRepositoryArtifact} from '../../src/engines/repository-evidence.js';
const hex=b=>Buffer.from(b).toString('hex'),canonical=v=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?`[${v.map(canonical).join(',')}]`:`{${Object.keys(v).sort().map(k=>`${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
async function identity(){const pair=await webcrypto.subtle.generateKey('Ed25519',true,['sign','verify']);return{...pair,key:hex(await webcrypto.subtle.exportKey('raw',pair.publicKey))};}
async function sign(payload,key){const bytes=Buffer.from('scopeblind.coordination.v1\n'+canonical(payload));return{payload,signer:key.key,digest:createHash('sha256').update(bytes).digest('hex'),signature:hex(await webcrypto.subtle.sign('Ed25519',key.privateKey,bytes))};}
async function fixture(){
 const [owner,reviewer,receiver,service]=await Promise.all([identity(),identity(),identity(),identity()]),time=n=>new Date(1800000000000+n*1000).toISOString(),id='repository-task-test';
 const task=await sign({type:'scopeblind.repository.task.v1',id,title:'Website correction',repository:'scopeblind/demo',pull_number:1,base_branch:'main',owner_key:owner.key,receiver_key:receiver.key,authority_key:service.key,allowed_paths:['site/**'],required_checks:[{name:'website-checks',app_id:15368}],reviewer_secret_hash:'a'.repeat(64),issued_at:time(0),expires_at:time(3600)},owner);
 const claim=await sign({type:'scopeblind.repository.claim.v1',task_id:id,task_digest:task.digest,reviewer_key:reviewer.key,name:'Jamie',issued_at:time(1)},reviewer);
 const proposal=await sign({type:'scopeblind.repository.proposal.v1',id:'proposal-test',task_id:id,task_digest:task.digest,repository_id:'R_demo',base_ref:'refs/heads/main',head_ref:'refs/heads/feature',base_sha:'1'.repeat(40),head_sha:'2'.repeat(40),merge_sha:'3'.repeat(40),tree_sha:'4'.repeat(40),files:[{path:'site/index.html',status:'modified',mode:'100644',additions:1,deletions:1,patch:'-before\n+after'}],checks:[{id:12,name:'website-checks',app_id:15368,head_sha:'2'.repeat(40),conclusion:'success'}],observed_at:time(2)},receiver);
 const approvals=await Promise.all([['owner',owner],['reviewer',reviewer]].map(([role,key])=>sign({type:'scopeblind.repository.approval.v1',task_id:id,task_digest:task.digest,proposal_digest:proposal.digest,role,principal_key:key.key,decision:'approve',issued_at:time(3),expires_at:time(303),note:'Reviewed exact change'},key)));
 const execution=await sign({type:'scopeblind.repository.execution.v1',operation_id:'repo-task-test',receiver_attempt_id:'attempt-test',task_id:id,task_digest:task.digest,proposal_digest:proposal.digest,owner_approval_digest:approvals[0].digest,reviewer_approval_digest:approvals[1].digest,receiver_key:receiver.key,action:'github.updateRefs',issued_at:time(4),expires_at:time(124)},service);
 const outcome=await sign({type:'scopeblind.repository.outcome.v1',operation_id:execution.payload.operation_id,task_id:id,task_digest:task.digest,proposal_digest:proposal.digest,execution_digest:execution.digest,status:'confirmed',observed_base_sha:proposal.payload.merge_sha,readback:'exact_ref',observed_at:time(5),note:'Receiver read the exact resulting ref'},receiver);
 const acceptance=await sign({type:'scopeblind.repository.acceptance.v1',task_id:id,task_digest:task.digest,outcome_digest:outcome.digest,reviewer_key:reviewer.key,decision:'accept',issued_at:time(6),note:'Accepted'},reviewer);
 const state=await sign({type:'scopeblind.repository.state.v1',task,reviewer:claim,proposal,approvals,execution,outcome,acceptance,status:'accepted',revision:7,observed_at:time(7)},service);
 return{evidence:{type:'scopeblind.repository.evidence.v1',state},owner,reviewer,receiver,service};
}

test('repository format verifies exact signed statements, distinguishes pins, outcome and acceptance',async()=>{
 const f=await fixture();assert.equal(detectFormat(f.evidence).mode,'repository-evidence');const unpinned=await verifyRepositoryArtifact(f.evidence);assert.equal(unpinned.valid,true,JSON.stringify(unpinned));assert.equal(unpinned.authorityPinned,false);assert.equal(unpinned.accepted,true);assert.match(unpinned.not_established.join(' '),/not a GitHub-signed receipt/);assert.match(unpinned.not_established.join(' '),/No independent authority key/);
 assert.equal((await verifyRepositoryArtifact(f.evidence,{publicKey:f.service.key})).authorityPinned,true);assert.equal((await verifyRepositoryArtifact(f.evidence,{publicKey:f.owner.key})).valid,false);
});

test('offline verifier rejects altered signatures, false signed status, changed proposal and overlong authorization',async()=>{
 const f=await fixture(),state=f.evidence.state.payload;
 const changed=structuredClone(f.evidence);changed.state.payload.outcome.payload.observed_base_sha='9'.repeat(40);assert.equal((await verifyRepositoryArtifact(changed)).valid,false);
 const cases=[{...state,acceptance:null,status:'accepted'}, {...state,proposal:await sign({...state.proposal.payload,head_sha:'9'.repeat(40)},f.receiver)}, {...state,execution:await sign({...state.execution.payload,expires_at:state.task.payload.expires_at},f.service)}, {...state,outcome:await sign({...state.outcome.payload,readback:'not_confirmed'},f.receiver)}];
 for(const payload of cases){const evidence={type:f.evidence.type,state:await sign(payload,f.service)};assert.equal((await verifyRepositoryArtifact(evidence)).valid,false);}
 const noAcceptance={...state,acceptance:null,status:'confirmed'};const result=await verifyRepositoryArtifact({type:f.evidence.type,state:await sign(noAcceptance,f.service)});assert.equal(result.valid,true);assert.equal(result.accepted,false);
});

test('actual CLI auto-detects an exported repository artifact and reports explicit trust limits offline',async()=>{
 const f=await fixture(),dir=await mkdtemp(join(tmpdir(),'scopeblind-repository-verify-'));try{const file=join(dir,'evidence.json');await writeFile(file,JSON.stringify(f.evidence));const result=spawnSync(process.execPath,['cli.js',file,'--key',f.service.key,'--json'],{cwd:new URL('../..',import.meta.url),encoding:'utf8'});assert.equal(result.status,0,result.stderr+result.stdout);const report=JSON.parse(result.stdout);assert.equal(report.format,'repository-evidence');assert.equal(report.authorityPinned,true);assert.equal(report.accepted,true);assert.match(report.not_established.join(' '),/Other credentials/);}finally{await rm(dir,{recursive:true,force:true});}
});
