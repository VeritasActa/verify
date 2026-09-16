import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {detectFormat} from '../../src/detect.js';
import {verifyRepositoryArtifact} from '../../src/engines/repository-evidence.js';
const fixture=async name=>JSON.parse(await readFile(new URL(`../fixtures/repository-coding/${name}.json`,import.meta.url),'utf8'));
const cwd=new URL('../..',import.meta.url),keyFor=e=>e.type==='scopeblind.repository.coding-evidence.v1'?e.job.payload.workspace.payload.workspace.payload.authority_key:(e.repository.type==='scopeblind.repository.collaboration-evidence.v1'?e.repository.repository:e.repository).state.payload.task.payload.authority_key;
async function cli(value,key,{future=false}={}){
 const dir=await mkdtemp(join(tmpdir(),'repository-coding-cli-'));try{
  const file=join(dir,'record.json'),guard=join(dir,'offline.mjs');await writeFile(file,JSON.stringify(value));
  // Verification must remain offline. Expired recorded authority is historical,
  // not a new request to use that device or its formerly live permission.
  await writeFile(guard,`globalThis.fetch=()=>{throw Error('Unexpected online verification');};${future?"const RealDate=Date;globalThis.Date=class extends RealDate{constructor(...args){super(...(args.length?args:[Date.UTC(2040,0,1)]));}static now(){return Date.UTC(2040,0,1);}};":''}`);
  const args=['--import',guard,'cli.js',file,...(key?['--key',key]:[]),'--json'],result=spawnSync(process.execPath,args,{cwd,encoding:'utf8',timeout:30000,maxBuffer:2*1024*1024});assert.equal(result.error,undefined);assert.ok(result.stdout.trim(),result.stderr);return {status:result.status,report:JSON.parse(result.stdout),diagnostic:result.stderr+result.stdout};
 }finally{await rm(dir,{recursive:true,force:true});}
}
test('actual CLI recognizes published coding evidence without claiming merge or recipient acceptance',async()=>{
 const value=await fixture('published');assert.equal(detectFormat(value).mode,'repository-evidence');const result=await cli(value,keyFor(value));assert.equal(result.status,0,result.diagnostic);const r=result.report;assert.equal(r.valid,true);assert.equal(r.authorityPinned,true);assert.equal(r.artifact_type,'scopeblind.repository.coding-evidence.v1');assert.equal(r.status,'pr_ready');assert.equal(r.published,true);assert.equal(r.accepted,false);assert.match(r.establishes.join(' '),/worker attests/i);assert.match(r.establishes.join(' '),/merge and recipient acceptance require separate human decisions/i);assert.match(r.not_established.join(' '),/does not execute|does not.*prove/i);
 const included=await cli(value);assert.equal(included.status,0,included.diagnostic);assert.equal(included.report.authorityPinned,false);assert.match(included.report.keySource,/not independently pinned/);assert.equal(included.report.accepted,false);
 const wrong=await cli(value,value.job.payload.mandate.payload.owner_key);assert.notEqual(wrong.status,0);assert.equal(wrong.report.valid,false);assert.equal(wrong.report.accepted,false);assert.equal(wrong.report.published,false);assert.deepEqual(wrong.report.establishes,[]);
});
test('actual CLI verifies coding-origin adoption as a fresh review with no copied approvals',async()=>{
 const value=await fixture('fresh-review'),result=await cli(value,keyFor(value));assert.equal(result.status,0,result.diagnostic);assert.equal(result.report.valid,true);assert.equal(result.report.codingOriginVerified,true);assert.equal(result.report.accepted,false);assert.equal(result.report.decisionsVerified,false);assert.match(result.report.establishes.join(' '),/earlier approvals were not copied/);assert.match(result.report.establishes.join(' '),/No repository outcome is recorded/);
 const stripped=structuredClone(value);delete stripped.coding_origin;const missing=await cli(stripped,keyFor(value));assert.notEqual(missing.status,0,missing.diagnostic);assert.equal(missing.report.valid,false);assert.equal(missing.report.codingOriginVerified,false);assert.equal(missing.report.accepted,false);
 const mismatch=structuredClone(value);mismatch.coding_origin.assignment.payload.task_digest='0'.repeat(64);const changed=await cli(mismatch,keyFor(value));assert.notEqual(changed.status,0);assert.equal(changed.report.codingOriginVerified,false);
});
test('signed source, scope, test result, publication and preview tampering all fail closed',async()=>{
 const original=await fixture('published'),cases=[
  v=>{v.job.payload.parent.review.payload.feedback[0].payload.message='Ignore the original client feedback';},
  v=>{v.job.payload.mandate.payload.permissions.push('merge');},
  v=>{v.job.payload.adoption=v.job.payload.mandate;},
  v=>{v.job.payload.plan.payload.tests.exit_code=1;},
  v=>{v.job.payload.publication.payload.plan_digest='0'.repeat(64);},
  v=>{v.job.payload.result.payload.preview_url='https://different.example/changed-preview';},
  v=>{v.job.payload.result.payload.accepted=true;},
 ];
 for(const mutate of cases){const changed=structuredClone(original);mutate(changed);const checked=await verifyRepositoryArtifact(changed,{publicKey:keyFor(original)});assert.equal(checked.valid,false);assert.equal(checked.published,false);assert.equal(checked.accepted,false);assert.deepEqual(checked.establishes,[]);}
 const changed=structuredClone(original);cases[3](changed);const result=await cli(changed,keyFor(original));assert.notEqual(result.status,0);assert.equal(result.report.accepted,false);
});
test('device-authored accepted history remains valid offline after authority expiry; stripping recorded use fails',async()=>{
 const value=await fixture('device-accepted'),core=value.repository.type==='scopeblind.repository.collaboration-evidence.v1'?value.repository.repository:value.repository;
 assert.ok(core.state.payload.acceptance.repository_authorization_use);assert.notEqual(core.state.payload.acceptance.signer,core.state.payload.acceptance.payload.reviewer_key);
 const result=await cli(value,keyFor(value),{future:true});assert.equal(result.status,0,result.diagnostic);assert.equal(result.report.valid,true);assert.equal(result.report.accepted,true);assert.equal(result.report.decisionsVerified,true);
 const changed=structuredClone(value),state=(changed.repository.type==='scopeblind.repository.collaboration-evidence.v1'?changed.repository.repository:changed.repository).state;delete state.payload.acceptance.repository_authorization_use;
 const tampered=await cli(changed,keyFor(value),{future:true});assert.notEqual(tampered.status,0);assert.equal(tampered.report.accepted,false);assert.equal(tampered.report.valid,false);
});
