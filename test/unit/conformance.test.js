import test from 'node:test';
import assert from 'node:assert/strict';
import {detectTier} from '../../src/conformance.js';
const checked={valid:true,signatureVerified:true,jcsVerified:true};
test('declared metadata never grants assurance',()=>{
 const r=detectTier({...checked,payloadFields:{holder_binding:'claimed',attestation_mode:'hardware',anchor_uri:'https://untrusted.example',previousReceiptHash:'claimed'}});
 assert.equal(r.tier,1);assert.deepEqual(r.features,['ed25519-signature','jcs-canonicalization']);assert.equal(r.declaredFeatures.length,4);
});
test('mode and failed result cannot grant assurance',()=>{
 for(const valid of [false,undefined]) {const r=detectTier({valid,mode:'voprf-token',voprfVerified:true,disclosuresVerified:3});assert.equal(r.tier,0);assert.deepEqual(r.features,[]);}
 assert.equal(detectTier({...checked,mode:'voprf-token'}).tier,1);
});
test('explicit checked capabilities determine the reported level',()=>{
 assert.equal(detectTier({...checked,disclosuresVerified:2}).tier,2);
 assert.equal(detectTier({...checked,attestationVerified:true}).tier,3);
 assert.equal(detectTier({...checked,anchorVerified:true}).tier,3);
 assert.equal(detectTier({valid:true,voprfVerified:true}).tier,4);
 assert.deepEqual(detectTier({valid:true,voprfVerified:true}).features,['voprf']);
 assert.equal(detectTier({...checked,disclosuresVerified:'3'}).tier,1);
});
test('legacy signature does not claim JCS or unverified chain',()=>{
 const r=detectTier({valid:true,signatureVerified:true,jcsVerified:false,payloadFields:{previousReceiptHash:'a'}});
 assert.deepEqual(r.features,['ed25519-signature']);assert.deepEqual(r.declaredFeatures,['chain-linkage']);
});
