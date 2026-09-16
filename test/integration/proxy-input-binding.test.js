import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {generateKeyPairSync,createHash,verify} from 'node:crypto';
import {mkdtempSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {canonicalize,canonicalizeJson} from '../../src/util/canonical.js';

test('real MCP relay signs complete forwarded nested arguments and chains both receipts', {timeout:20000},async()=>{
 const dir=mkdtempSync(join(tmpdir(),'acta-proxy-wire-'));
 const pair=generateKeyPairSync('ed25519');
 const key=join(dir,'key.json');
 writeFileSync(key,JSON.stringify({kid:'wire-test',privateDer:pair.privateKey.export({format:'der',type:'pkcs8'}).toString('hex'),pubHex:pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex')}),{mode:0o600});
 // A child process sees only what the actual proxy forwards, not test-side reconstruction.
 const child=join(dir,'target.cjs');
 writeFileSync(child,`const rl=require('node:readline').createInterface({input:process.stdin});let n=0;rl.on('line',l=>{const m=JSON.parse(l);process.stdout.write(JSON.stringify({id:m.id,result:m.params.arguments})+'\\n');if(++n===2)process.exit(0);});`);
 const cli=fileURLToPath(new URL('../../cli.js',import.meta.url));
 const proc=spawn(process.execPath,[cli,'proxy','--target',`${process.execPath} ${child}`,'--attest-key',key,'--receipts-dir',join(dir,'receipts'),'--scrub-secrets'],{cwd:dir,stdio:['pipe','pipe','pipe']});
 let stdout='',stderr='';proc.stdout.on('data',d=>stdout+=d);proc.stderr.on('data',d=>stderr+=d);
 try{
  for(const [i,args] of [null,false,0,'',[]].entries())proc.stdin.write(JSON.stringify({jsonrpc:'2.0',id:-i,method:'tools/call',params:{name:'pay',arguments:args}})+'\n');
  for(const [id,amount] of [[1,120],[2,990]])proc.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method:'tools/call',params:{name:'pay',arguments:{payment:{amount,account:{token:'a-secret',destination:'supplier'}},numeric:{'2':2,'10':10}}}})+'\n');
  const code=await new Promise((resolve,reject)=>{proc.once('error',reject);proc.once('close',resolve);});
  assert.equal(code,0,stderr);const responses=stdout.trim().split('\n').map(l=>JSON.parse(l));assert.equal(responses.length,7);assert.equal(responses.filter(r=>r.error?.code===-32602).length,5);const forwarded=responses.filter(r=>r.id>0);assert.equal(forwarded.length,2);
  const receipts=[1,2].map(n=>JSON.parse(readFileSync(join(dir,'receipts',`rcpt_${String(n).padStart(6,'0')}.json`),'utf8')));
  for(let i=0;i<2;i++){
   const args=forwarded[i].result,r=receipts[i];assert.equal(args.payment.account.token,'REDACTED_BY_PROXY');assert.equal(args.payment.amount,i?990:120);
   assert.equal(r.payload.tool_input_hash_method,'jcs-sha256-v1');
   assert.equal(r.payload.tool_input_hash,'sha256:'+createHash('sha256').update(canonicalizeJson(args)).digest('hex'));
   assert.equal(verify(null,Buffer.from(canonicalize(r.payload)),pair.publicKey,Buffer.from(r.signature.sig,'hex')),true);
   assert.equal(JSON.stringify(r).includes('a-secret'),false);
  }
  assert.notEqual(receipts[0].payload.tool_input_hash,receipts[1].payload.tool_input_hash);
  assert.equal(receipts[1].payload.previousReceiptHash,'sha256:'+createHash('sha256').update(canonicalize(receipts[0])).digest('hex'));
 }finally{proc.kill();rmSync(dir,{recursive:true,force:true});}
});
