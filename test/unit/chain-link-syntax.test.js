import test from 'node:test';
import assert from 'node:assert/strict';
import {ed25519} from '@noble/curves/ed25519';
import {bytesToHex,utf8ToBytes} from '@noble/hashes/utils';
import {canonicalize} from '../../src/util/canonical.js';
import {verifyReceipt,checkChainLinkSyntax} from '../../src/engines/ed25519-receipt.js';
const secret=new Uint8Array(32).fill(11),publicKey=bytesToHex(ed25519.getPublicKey(secret));
const sign=(fields)=>bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(fields)),secret));
const envelope=(payload)=>({payload,signature:{alg:'EdDSA',kid:'test',sig:sign(payload)}});
const fields={type:'protectmcp:decision',issued_at:'2026-10-12T00:00:00Z',tool_name:'records.share',decision:'allow'};
const digest='ab'.repeat(32);
const withLink=(link)=>envelope({...fields,previousReceiptHash:link});
const check=async(e)=>verifyReceipt(e,'ed25519-passport',{publicKey});

test('a well-formed link and the bare digest of earlier revisions verify (draft §6.7)',async()=>{
 const prefixed=await check(withLink(`sha256:${digest}`));assert.equal(prefixed.valid,true);assert.equal(prefixed.chainLink,'sha256');
 const bare=await check(withLink(digest));assert.equal(bare.valid,true);assert.equal(bare.chainLink,'legacy-bare-hex');
 const genesis=await check(envelope(fields));assert.equal(genesis.valid,true);assert.equal(genesis.chainLink,undefined);
});

test('a signed receipt whose link is malformed is refused without a predecessor (draft §6.7)',async()=>{
 for(const link of ['sha256:not-a-digest',`sha256:${'CD'.repeat(32)}`,`SHA256:${digest}`,`sha256:${digest}0`,`sha256:${digest.slice(2)}`,`sha256:${digest} `,'not-a-digest','',digest.toUpperCase(),42,{sha256:digest},[digest]]){
  const e=withLink(link);
  assert.equal(ed25519.verify(e.signature.sig,utf8ToBytes(canonicalize(e.payload)),publicKey),true,'the bytes are genuinely signed');
  const r=await check(e);
  assert.equal(r.valid,false,JSON.stringify(link));assert.equal(r.error,'malformed_chain_link',JSON.stringify(link));
 }
});

test('a link naming another algorithm is refused rather than read as SHA-256 (draft §6.7)',async()=>{
 for(const link of [`sha512:${'ab'.repeat(64)}`,`sha384:${'ab'.repeat(48)}`,`sha-256:${digest}`,`blake3:${digest}`]){
  const r=await check(withLink(link));
  assert.equal(r.valid,false,link);assert.equal(r.error,'unsupported_chain_hash_algorithm',link);
 }
});

test('a tampered receipt still reports invalid_signature, whatever its link',async()=>{
 const e=withLink('sha256:not-a-digest');e.payload.decision='deny';
 const r=await check(e);assert.equal(r.valid,false);assert.equal(r.error,'invalid_signature');
});

test('a null link, which earlier tools wrote on the first receipt, verifies with a warning (draft §2.2)',async()=>{
 const r=await check(withLink(null));
 assert.equal(r.valid,true);assert.equal(r.chainLink,'null');assert.match(r.warning,/§2\.2/);
});

test('the flat and v2 shapes are checked the same way',async()=>{
 const flatFields={...fields,previousReceiptHash:'sha256:not-a-digest'};
 const flat={...flatFields,signature:sign(flatFields)};
 const rf=await verifyReceipt(flat,'ed25519-receipt-v1',{publicKey});assert.equal(rf.valid,false);assert.equal(rf.error,'malformed_chain_link');
 const v2Signed={v:2,kid:'test',issuer:'test',issued_at:fields.issued_at,payload:{...fields,previousReceiptHash:`sha512:${'ab'.repeat(64)}`}};
 const v2={...v2Signed,signature:sign(v2Signed)};
 const r2=await verifyReceipt(v2,'ed25519-receipt-v2',{publicKey});assert.equal(r2.valid,false);assert.equal(r2.error,'unsupported_chain_hash_algorithm');
});

test('checkChainLinkSyntax reports the form it accepted',()=>{
 assert.deepEqual(checkChainLinkSyntax({}),{form:undefined,warning:undefined});
 assert.equal(checkChainLinkSyntax({previousReceiptHash:`sha256:${digest}`}).form,'sha256');
 assert.equal(checkChainLinkSyntax({previousReceiptHash:digest}).form,'legacy-bare-hex');
 assert.equal(checkChainLinkSyntax({previousReceiptHash:'sha256:x'}).error,'malformed_chain_link');
 assert.equal(checkChainLinkSyntax({previousReceiptHash:'sha512:x'}).error,'unsupported_chain_hash_algorithm');
});
