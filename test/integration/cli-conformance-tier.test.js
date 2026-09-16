import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {ed25519} from '@noble/curves/ed25519';
import {bytesToHex,utf8ToBytes} from '@noble/hashes/utils';
import {canonicalize,legacyCanonicalize} from '../../src/util/canonical.js';

const secret=new Uint8Array(32).fill(19);
const publicKey=bytesToHex(ed25519.getPublicKey(secret));
const cli=fileURLToPath(new URL('../../cli.js',import.meta.url));

function receipt(payload,encoding=canonicalize) {
 return {payload,signature:{alg:'EdDSA',kid:'tier-test',sig:bytesToHex(ed25519.sign(utf8ToBytes(encoding(payload)),secret))}};
}
function run(input,tier,extra=[]) {
 const child=spawnSync(process.execPath,[cli,'--stdin','--key',publicKey,'--json','--tier',String(tier),...extra],{input:JSON.stringify(input),encoding:'utf8',timeout:10000});
 assert.ifError(child.error);
 assert.notEqual(child.status,null,child.stderr);
 return {status:child.status,result:JSON.parse(child.stdout)};
}

test('CLI preserves T0 for an invalid signature under minimum-tier requirements',()=>{
 const input=receipt({type:'test',amount:100});
 input.payload.amount=999;
 for(const tier of [1,2]) {
  const {status,result}=run(input,tier);
  assert.notEqual(status,0);
  assert.equal(result.valid,false);
  assert.equal(result.tier.tier,0);
  assert.deepEqual(result.tier.features,[]);
  assert.doesNotMatch(result.detail||'',/achieved T[1-5]/);
  assert.doesNotMatch(result.errorMeta?.description||'',/verification succeeded/i);
 }
});

test('CLI distinguishes verified T1 from unverified payload feature declarations',()=>{
 const input=receipt({type:'test',merkleRoot:'claimed-root',proof:['claimed-proof'],anchor:'claimed-anchor'});
 const t1=run(input,1);
 assert.equal(t1.status,0);
 assert.equal(t1.result.valid,true);
 assert.equal(t1.result.tier.tier,1);
 const t2=run(input,2);
 assert.notEqual(t2.status,0);
 assert.equal(t2.result.valid,false);
 assert.equal(t2.result.tier.tier,1);
 assert.match(t2.result.detail,/achieved T1/);
});

test('CLI legacy compatibility is explicit, labelled and overridden by strict mode',()=>{
 const input=receipt({type:'test',nested:{'2':2,'10':10}},legacyCanonicalize);
 const refused=run(input,1);
 assert.notEqual(refused.status,0);
 assert.equal(refused.result.valid,false);
 assert.equal(refused.result.tier.tier,0);
 const allowed=run(input,1,['--allow-legacy-canonicalization']);
 assert.equal(allowed.status,0);
 assert.equal(allowed.result.valid,true);
 assert.equal(allowed.result.canonicalization,'legacy-numeric-key-order');
 assert.match(allowed.result.warning,/not RFC 8785/);
 assert.equal(allowed.result.tier.features.includes('jcs-canonicalization'),false);
 const strict=run(input,1,['--allow-legacy-canonicalization','--strict']);
 assert.notEqual(strict.status,0);
 assert.equal(strict.result.valid,false);
 assert.equal(strict.result.tier.tier,0);
});
