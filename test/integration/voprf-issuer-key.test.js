/**
 * VOPRF tokens on the CLI: the issuer key comes from --key, and a token is never verified against the key it carries
 * (draft §9.5). Before, the CLI handed --key to the engine under a name it never read, and the engine fell back to the
 * token's own issuer_public_key, so a token self-issued under a fresh key verified (exit 0, "T4 privacy") with no key,
 * with a victim's --key, and under --strict. A BRASS 2.0 redemption was not detected (unknown_format), and with
 * --mode voprf was refused for want of a key (issuer_key_pin_required) whatever --key said, so none ever verified.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { p256, hashToCurve } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
import { G, modN, bytesToBig, Hlabel, DLEQ_LABEL, encodePoint } from '../../src/util/voprf-crypto.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'acta-voprf-key-'));
const write = (name, value) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(value)); return p; };
const run = (...args) => spawnSync(process.execPath, [cli, ...args, '--json'], { encoding: 'utf8', timeout: 30000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
const json = (...args) => { const r = run(...args); return { status: r.status, report: JSON.parse(r.stdout) }; };

const N = p256.CURVE.n;
const scalar = () => modN(bytesToBig(randomBytes(32))) || 1n;
const b64 = (bytes) => Buffer.from(bytes).toString('base64url');
const b32 = (x) => b64(Buffer.from(x.toString(16).padStart(64, '0'), 'hex'));
const victimKey = encodePoint(G.multiply(scalar()));

// (A) The report's legacy token: an issuer key the attacker chose, and an issuer proof made under it.
function selfIssued() {
  const k = scalar(), m = scalar(), t = scalar();
  const Y = G.multiply(k), M = G.multiply(m), Z = M.multiply(k);
  const A1 = G.multiply(t), A2 = M.multiply(t);
  const c = modN(bytesToBig(Hlabel(DLEQ_LABEL, G.toRawBytes(true), Y.toRawBytes(true), M.toRawBytes(true), Z.toRawBytes(true), A1.toRawBytes(true), A2.toRawBytes(true), new Uint8Array(0))));
  const r = modN(t - c * k);
  return {
    algorithm: 'voprf-p256-sha256', kid: 'attacker-issuer', issuer_public_key: encodePoint(Y),
    origin: 'https://victim.example', epoch: 1, nullifier: 'self-issued',
    M: encodePoint(M), Z: encodePoint(Z), Zprime: encodePoint(G.multiply(scalar())), piI: { c: b32(c), r: b32(r) },
  };
}

test('cli: a self-issued legacy token is invalid under a victim\'s --key, and undecidable with none', () => {
  const token = selfIssued();
  const file = write('legacy-self-issued.json', token);
  for (const extra of [['--mode', 'voprf'], [], ['--strict']]) {
    const { status, report } = json(file, '--key', victimKey, ...extra);
    assert.equal(status, 1, `${extra.join(' ')}: ${JSON.stringify(report)}`);
    assert.equal(report.valid, false);
    assert.equal(report.error, 'issuer_key_mismatch');
  }
  const none = json(file);
  assert.equal(none.status, 2, JSON.stringify(none.report));
  assert.equal(none.report.error, 'missing_issuer_public_key');
  // With the carried key removed, the issuer proof itself fails under the victim's key.
  const bare = { ...token };
  delete bare.issuer_public_key;
  const stripped = json(write('legacy-bare.json', bare), '--key', victimKey);
  assert.equal(stripped.status, 1, JSON.stringify(stripped.report));
  assert.equal(stripped.report.error, 'invalid_piI');
  // Under the key that did issue it, it is what it is: a token from that issuer.
  const own = json(file, '--key', token.issuer_public_key);
  assert.equal(own.status, 0, JSON.stringify(own.report));
});

// (B) A BRASS 2.0 redemption, made here from the transcript src/util/brass-v2.js checks: the scope point, the blinded
// element, the issuer's evaluation and proof, the unblinded element and the client proof over the bind.
const Point = p256.ProjectivePoint;
const u32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const bytesOf = (v) => (v instanceof Uint8Array ? v : typeof v === 'number' ? u32(v) : utf8ToBytes(String(v)));
const H3 = (...parts) => sha256(Buffer.concat(parts.flatMap((p) => { const b = bytesOf(p); return [u32(b.length), b]; })));
const challenge = (g1, h1, g2, h2, a1, a2, bind) => modN(bytesToBig(H3(`BRASS:${DLEQ_LABEL}:`, ...[g1, h1, g2, h2, a1, a2].map((x) => x.toRawBytes(true)), bind)));
const prove = (g1, h1, g2, h2, secret, bind) => {
  const t = scalar();
  const c = challenge(g1, h1, g2, h2, g1.multiply(t), g2.multiply(t), bind);
  return { c: b32(c), z: b32(modN(t - c * secret)) };
};
const inverse = (a) => { let [r0, r1, s0, s1] = [a, N, 1n, 0n]; while (r1) { const q = r0 / r1; [r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1]; } return modN(s0); };

function brassV2() {
  const k = scalar(), r = scalar();
  const Y = G.multiply(k);
  const scope = 'opaque-scope-test';
  const P = Point.fromHex(hashToCurve(utf8ToBytes(scope), { DST: 'BRASS-P256_XMD:SHA-256_SSWU_RO_SCOPE-v1' }).toRawBytes(true));
  const M = P.multiply(r), Z = M.multiply(k), Zprime = Z.multiply(inverse(r));
  const token = {
    type: 'scopeblind.brass.redemption.v2', protocol: 'BRASS', version: '2.0', algorithm: 'voprf-p256-sha256',
    kid: 'brass-v2-test', issuer_public_key: encodePoint(Y), scope, origin: 'https://scopeblind.com', epoch: 1,
    policy: 'run-entitlement', window: 1, aadr: 'run:test', d: 'run-digest', c_nonce: encodePoint(G.multiply(scalar())),
    P: encodePoint(P), M: encodePoint(M), Z: encodePoint(Z), Zprime: encodePoint(Zprime),
  };
  token.piI = prove(G, Y, M, Z, k, new Uint8Array(0));
  const eta = H3('BRASS_SALT_v1', token.issuer_public_key, token.origin, String(token.epoch), String(token.policy), String(token.window));
  token.piC = prove(P, M, Zprime, Z, r, H3('BRASS:BIND:', token.c_nonce, token.d, eta, H3('no_exporter')));
  return token;
}

test('cli: a BRASS 2.0 redemption is detected and verifies under its issuer\'s --key, and only under it', () => {
  const token = brassV2();
  const file = write('brass-v2.json', token);
  for (const extra of [[], ['--mode', 'voprf']]) {
    const { status, report } = json(file, '--key', token.issuer_public_key, ...extra);
    assert.equal(status, 0, `${extra.join(' ')}: ${JSON.stringify(report)}`);
    assert.equal(report.protocolVersion, '2.0');
    assert.deepEqual(report.dleq, { issuer: true, client: true });
  }
  const other = json(file, '--key', victimKey);
  assert.equal(other.status, 1, JSON.stringify(other.report));
  assert.equal(other.report.error, 'issuer_key_mismatch');
  const none = json(file);
  assert.equal(none.status, 2, JSON.stringify(none.report));
  assert.equal(none.report.error, 'issuer_key_pin_required');
  const tampered = json(write('brass-v2-tampered.json', { ...token, d: 'another-run' }), '--key', token.issuer_public_key);
  assert.equal(tampered.status, 1, JSON.stringify(tampered.report));
  assert.equal(tampered.report.error, 'invalid_piC');
});
