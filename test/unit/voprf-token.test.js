/**
 * Round-trip tests for the VOPRF engine.
 *
 * Uses the production BRASS issuer + client logic directly (ported
 * verbatim from brass-proof-public/worker/issuer-cloudflare.js and
 * client/src/lib/brass-strict-client.js) to generate tokens, then
 * verifies them through the engine. Negative tests tamper with the
 * emitted token and confirm rejection.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';

import { verifyVoprfToken } from '../../src/engines/voprf-token.js';

const G = p256.ProjectivePoint.BASE;
const N = p256.CURVE.n;

function modN(x) { const r = x % N; return r < 0n ? r + N : r; }
function bytesToBig(b) {
  let n = 0n;
  for (const byte of b) n = (n << 8n) | BigInt(byte);
  return n;
}
function bigToBytes32(x) {
  let hex = x.toString(16);
  if (hex.length & 1) hex = '0' + hex;
  const bytes = new Uint8Array(32);
  const buf = Buffer.from(hex, 'hex');
  bytes.set(buf, 32 - buf.length);
  return bytes;
}
function b64u(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64ud(s) {
  let b = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b.length % 4) b += '=';
  return new Uint8Array(Buffer.from(b, 'base64'));
}
function u8(s) { return typeof s === 'string' ? utf8ToBytes(s) : s; }
function H(...parts) {
  const byteParts = parts.map(p => u8(p));
  let total = 0;
  for (const p of byteParts) total += p.length;
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of byteParts) { buf.set(p, off); off += p.length; }
  return sha256(buf);
}
function Hlabel(label, ...parts) { return H(`BRASS:${label}:`, ...parts); }
function randomScalar() {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  let s = modN(bytesToBig(bytes));
  return s === 0n ? 1n : s;
}
function randomPoint() {
  return G.multiply(randomScalar());
}

// ─── Prover ────────────────────────────────────────────────────────────────

/**
 * Produce a BRASS VOPRF token exactly as the production issuer
 * (issuer-cloudflare.js) and the production client
 * (brass-strict-client.js) do.
 */
function generateToken({
  issuerK,
  origin = 'https://api.example.com',
  epoch = 20220,
  KID = 'kid-test',
  AADr = 'scope=api.example.com|policy=default',
  withClientProof = true,
  tamperIssuerR = null,
  tamperClientR = null,
  tamperAADr = null,
}) {
  const k = issuerK;
  const Y = G.multiply(k);

  // Scope point P (chosen deterministically from scope for this test)
  const scopeSeed = Hlabel('SCOPE_POINT_v1', origin, String(epoch), AADr);
  const pScalar = modN(bytesToBig(scopeSeed)) || 1n;
  const P = G.multiply(pScalar);

  // Client blinding scalar r, blinded element M = r·P
  const r_blind = randomScalar();
  const M = P.multiply(r_blind);

  // Issuer evaluation Z = k·M, and πI over (G, Y, M, Z)
  const Z = M.multiply(k);
  let alpha = randomScalar();
  const A1i = G.multiply(alpha);
  const A2i = M.multiply(alpha);
  const cI_raw = Hlabel(
    'OPRF_METERING_DLEQ_v1',
    G.toRawBytes(true), Y.toRawBytes(true),
    M.toRawBytes(true), Z.toRawBytes(true),
    A1i.toRawBytes(true), A2i.toRawBytes(true)
  );
  const cI = modN(bytesToBig(cI_raw));
  let rI = modN(alpha - cI * k);
  if (tamperIssuerR) rI = modN(rI + 1n);
  const piI = {
    c: b64u(bigToBytes32(cI)),
    r: b64u(bigToBytes32(rI)),
  };

  // Unblinded token Z' = Z · r⁻¹ (client unblinding).
  // Note: in the production protocol Z' = k·P, which equals r⁻¹·Z
  // because Z = k·M = k·(r·P) = r·(k·P) = r·Z'.
  const rInv = modInverse(r_blind, N);
  const Zprime = Z.multiply(rInv);

  // Nullifier inputs
  const eta = new Uint8Array(32); // zero salt for tests
  const yBytes = Hlabel(
    'OPRF_METERING_Y_v1',
    Zprime.toRawBytes(true),
    KID,
    AADr,
    eta,
  );
  const y = b64u(yBytes);

  // Random nonce c (client-chosen per redemption)
  const cNonce = new Uint8Array(16);
  for (let i = 0; i < cNonce.length; i++) cNonce[i] = Math.floor(Math.random() * 256);

  // d_client: HTTP context digest (sentinel value for tests)
  const d_client = Hlabel('HTTP_CTX_v1', 'POST', '/api/test', sha256(new Uint8Array(0)));

  // tlsHash: sentinel for non-TLS test environment
  const tlsHash = sha256(utf8ToBytes('BRASS:TLS_EXPORTER_v1:NO_TLS_EXPORTER_v1'));

  const token = {
    algorithm: 'voprf-p256-sha256',
    kid: KID,
    KID,
    AADr: tamperAADr || AADr,
    origin, epoch,
    issuer_public_key: b64u(Y.toRawBytes(true)),
    P: b64u(P.toRawBytes(true)),
    M: b64u(M.toRawBytes(true)),
    Z: b64u(Z.toRawBytes(true)),
    Zprime: b64u(Zprime.toRawBytes(true)),
    piI,
    y,
    eta: b64u(eta),
    c: b64u(cNonce),
    d_client: b64u(d_client),
    tlsHash: b64u(tlsHash),
    scope: { origin, epoch },
  };

  if (withClientProof) {
    // πC: client proves knowledge of r_blind such that M = r_blind·P.
    // Single-variable Schnorr with A2=G hardcoded (BRASS scheme).
    const bind = H(
      'BRASS_BIND_v1',
      b64ud(y),
      cNonce,
      d_client,
      u8(AADr),
      u8(KID),
      eta,
      tlsHash,
    );
    let kc = randomScalar();
    const A1c = P.multiply(kc);
    const A2c = G;
    const cC_raw = Hlabel(
      'OPRF_METERING_DLEQ_v1',
      P.toRawBytes(true), M.toRawBytes(true),
      G.toRawBytes(true), G.toRawBytes(true),
      A1c.toRawBytes(true), A2c.toRawBytes(true),
      bind,
    );
    const cC = modN(bytesToBig(cC_raw));
    let rC = modN(kc - cC * r_blind);
    if (tamperClientR) rC = modN(rC + 1n);
    token.piC = {
      c: b64u(bigToBytes32(cC)),
      r: b64u(bigToBytes32(rC)),
    };
  }

  return token;
}

/** Extended-Euclidean modular inverse. */
function modInverse(a, m) {
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error('not invertible');
  return modN(old_s);
}

// ─── Tests ─────────────────────────────────────────────────────────────────

test('VOPRF: valid token verifies with both piI and piC', async () => {
  const issuerK = randomScalar();
  const token = generateToken({ issuerK });
  const result = await verifyVoprfToken(token);
  assert.equal(result.valid, true, `unexpected result: ${JSON.stringify(result)}`);
  assert.equal(result.error, undefined);
  assert.equal(result.dleq.issuer, true);
  assert.equal(result.dleq.client, true);
  assert.ok(result.nullifier);
});

test('VOPRF: issuer-only token verifies (no piC)', async () => {
  const issuerK = randomScalar();
  const token = generateToken({ issuerK, withClientProof: false });
  const result = await verifyVoprfToken(token);
  assert.equal(result.valid, true);
  assert.equal(result.dleq.client, null);
});

test('VOPRF: tampered issuer r fails verification', async () => {
  const issuerK = randomScalar();
  const token = generateToken({ issuerK, tamperIssuerR: true });
  const result = await verifyVoprfToken(token);
  assert.equal(result.valid, false);
  assert.equal(result.error, 'invalid_piI');
});

test('VOPRF: tampered client r fails verification', async () => {
  const issuerK = randomScalar();
  const token = generateToken({ issuerK, tamperClientR: true });
  const result = await verifyVoprfToken(token);
  assert.equal(result.valid, false);
  assert.equal(result.error, 'invalid_piC');
});

test('VOPRF: tampered AADr breaks piC bind (production tokens) but piI is not AADr-bound', async () => {
  // The production scheme does NOT bind piI to AADr (bind=empty).
  // It DOES bind piC to AADr. So changing AADr after the fact
  // should break piC but not piI.
  const issuerK = randomScalar();
  const token = generateToken({ issuerK });
  token.AADr = 'scope=attacker.example.com|policy=elevated';
  const result = await verifyVoprfToken(token);
  assert.equal(result.valid, false);
  assert.equal(result.error, 'invalid_piC');
});

test('VOPRF: wrong issuer public key fails piI', async () => {
  const issuerK = randomScalar();
  const token = generateToken({ issuerK });
  const otherK = randomScalar();
  token.issuer_public_key = Buffer.from(G.multiply(otherK).toRawBytes(true)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const result = await verifyVoprfToken(token);
  assert.equal(result.valid, false);
  assert.equal(result.error, 'invalid_piI');
});

test('VOPRF: missing required field yields explicit error', async () => {
  const issuerK = randomScalar();
  const token = generateToken({ issuerK });
  delete token.M;
  const result = await verifyVoprfToken(token);
  assert.equal(result.valid, false);
  assert.equal(result.error, 'missing_field:M');
});

test('VOPRF: unsupported algorithm rejected', async () => {
  const result = await verifyVoprfToken({ algorithm: 'voprf-p521-sha512', M: 'x', Z: 'x', Zprime: 'x', piI: { c: 'x', r: 'x' } });
  assert.equal(result.valid, false);
  assert.equal(result.error, 'unsupported_algorithm');
});

test('VOPRF: missing issuer public key yields explicit error', async () => {
  const issuerK = randomScalar();
  const token = generateToken({ issuerK });
  delete token.issuer_public_key;
  const result = await verifyVoprfToken(token);
  assert.equal(result.valid, false);
  assert.equal(result.error, 'missing_issuer_public_key');
});

test('VOPRF: scope-mismatch rejection (opts.expectedScope)', async () => {
  const issuerK = randomScalar();
  const token = generateToken({ issuerK, origin: 'https://api.example.com' });
  const result = await verifyVoprfToken(token, { expectedScope: 'https://other.example.com' });
  assert.equal(result.valid, false);
  assert.equal(result.error, 'scope_mismatch');
});

test('VOPRF: requireClientProof rejects issuer-only token', async () => {
  const issuerK = randomScalar();
  const token = generateToken({ issuerK, withClientProof: false });
  const result = await verifyVoprfToken(token, { requireClientProof: true });
  assert.equal(result.valid, false);
  assert.equal(result.error, 'missing_piC');
});

test('VOPRF: nullifier is deterministic for same inputs', async () => {
  const issuerK = randomScalar();
  // Generate two tokens with the same Zprime + KID + AADr + eta.
  // The nullifier output must be identical because it is a pure
  // hash of those inputs.
  const token1 = generateToken({ issuerK });
  const r1 = await verifyVoprfToken(token1);
  const token2 = { ...token1, piC: undefined };  // strip piC, reverify
  const r2 = await verifyVoprfToken(token2);
  assert.equal(r1.valid, true);
  assert.equal(r2.valid, true);
  assert.equal(r1.nullifier, r2.nullifier);
});
