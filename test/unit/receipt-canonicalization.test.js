import test from 'node:test';
import assert from 'node:assert/strict';
import {ed25519} from '@noble/curves/ed25519';
import {bytesToHex,utf8ToBytes} from '@noble/hashes/utils';
import {canonicalize,legacyCanonicalize} from '../../src/util/canonical.js';
import {verifyReceipt} from '../../src/engines/ed25519-receipt.js';
const secret=new Uint8Array(32).fill(7),publicKey=bytesToHex(ed25519.getPublicKey(secret));
const envelope=(payload,encoding=canonicalize)=>({payload,signature:{alg:'EdDSA',kid:'test',sig:bytesToHex(ed25519.sign(utf8ToBytes(encoding(payload)),secret))}});
test('actual verifier checks JCS numeric keys and nested signature member',async()=>{
 const e=envelope({type:'test',nested:{'2':2,'10':10},signature:'payload field'});
 assert.equal((await verifyReceipt(e,'ed25519-passport',{publicKey})).valid,true);
 e.payload.signature='changed';assert.equal((await verifyReceipt(e,'ed25519-passport',{publicKey})).valid,false);
});
test('historical non-JCS signatures require explicit labelled compatibility',async()=>{
 const e=envelope({type:'test',nested:{'2':2,'10':10}},legacyCanonicalize);
 const strict=await verifyReceipt(e,'ed25519-passport',{publicKey});assert.equal(strict.valid,false);assert.equal(strict.error,'legacy_non_jcs_signature');assert.equal(strict.legacySignatureValid,true);
 const compat=await verifyReceipt(e,'ed25519-passport',{publicKey,allowLegacyCanonicalization:true});assert.equal(compat.valid,true);assert.equal(compat.canonicalization,'legacy-numeric-key-order');assert.match(compat.warning,/not RFC 8785/);
});
test('legacy fallback cannot authenticate an omitted prototype-named field',async()=>{
 const e=envelope({type:'test',nested:{'2':2,'10':10}},legacyCanonicalize);Object.defineProperty(e.payload,'__proto__',{value:{attack:true},enumerable:true});
 assert.equal((await verifyReceipt(e,'ed25519-passport',{publicKey,allowLegacyCanonicalization:true})).valid,false);
});

test('malformed hex pairs cannot alias a valid signature or key',async()=>{
 const {hexToBytes}=await import('../../src/util/hex.js');
 for(const value of ['bg','1g','g1','+1','-1'])assert.throws(()=>hexToBytes(value));
 let e,at=-1;
 for(let n=0;n<100&&at<0;n++){e=envelope({type:'test',nonce:n});at=e.signature.sig.match(/../g).findIndex(p=>p[0]==='0');}
 assert.ok(at>=0);const pairs=e.signature.sig.match(/../g);pairs[at]=pairs[at][1]+'g';e.signature.sig=pairs.join('');
 const r=await verifyReceipt(e,'ed25519-passport',{publicKey});assert.equal(r.valid,false);assert.equal(r.error,'malformed_encoding');
 const good=envelope({type:'test'});assert.equal((await verifyReceipt(good,'ed25519-passport',{publicKey:publicKey.slice(0,-2)+'bg'})).valid,false);
});
