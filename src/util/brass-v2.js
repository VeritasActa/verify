import { p256, hashToCurve } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { utf8ToBytes } from "@noble/hashes/utils";

const Point = p256.ProjectivePoint;
const G = Point.BASE;
const N = p256.CURVE.n;
const SCOPE_DST = "BRASS-P256_XMD:SHA-256_SSWU_RO_SCOPE-v1";
const DLEQ_LABEL = "OPRF_METERING_DLEQ_v1";

function modN(x) {
  const r = x % N;
  return r >= 0n ? r : r + N;
}

function bytesToBig(bytes) {
  let n = 0n;
  for (const byte of bytes) n = (n << 8n) | BigInt(byte);
  return n;
}

function u32be(n) {
  const out = new Uint8Array(4);
  out[0] = (n >>> 24) & 0xff;
  out[1] = (n >>> 16) & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = n & 0xff;
  return out;
}

function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (typeof value === "number") return u32be(value);
  return utf8ToBytes(String(value));
}

function H3(...parts) {
  const chunks = [];
  let length = 0;
  for (const part of parts) {
    const bytes = toBytes(part);
    const prefix = u32be(bytes.length);
    chunks.push(prefix, bytes);
    length += prefix.length + bytes.length;
  }
  const input = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    input.set(chunk, offset);
    offset += chunk.length;
  }
  return sha256(input);
}

function b64urlDecode(value) {
  return new Uint8Array(Buffer.from(String(value), "base64url"));
}

function b64urlEncode(value) {
  return Buffer.from(value).toString("base64url");
}

function decodePoint(value) {
  const point = Point.fromHex(b64urlDecode(value));
  point.assertValidity();
  if (point.equals(Point.ZERO)) throw new Error("invalid_point_infinity");
  return point;
}

function scopePoint(scope) {
  const point = hashToCurve(utf8ToBytes(String(scope)), { DST: SCOPE_DST });
  return Point.fromHex(point.toRawBytes(true));
}

function challenge(g1, h1, g2, h2, a1, a2, bind) {
  return modN(bytesToBig(H3(
    `BRASS:${DLEQ_LABEL}:`,
    g1.toRawBytes(true), h1.toRawBytes(true),
    g2.toRawBytes(true), h2.toRawBytes(true),
    a1.toRawBytes(true), a2.toRawBytes(true),
    bind || new Uint8Array(0),
  )));
}

function verifyDleq(g1, h1, g2, h2, proof, bind) {
  try {
    const c = modN(bytesToBig(b64urlDecode(proof.c)));
    const z = modN(bytesToBig(b64urlDecode(proof.z)));
    const a1 = g1.multiply(z).add(h1.multiply(c));
    const a2 = g2.multiply(z).add(h2.multiply(c));
    return challenge(g1, h1, g2, h2, a1, a2, bind) === c;
  } catch {
    return false;
  }
}

function deriveEta(input) {
  return H3(
    "BRASS_SALT_v1",
    input.issuer_public_key,
    input.origin,
    String(input.epoch),
    String(input.policy),
    String(input.window),
  );
}

/**
 * Verify the canonical BRASS 2.0 transcript used by Legate and the Pages
 * blind-evaluation endpoint. The caller must pin the issuer key and kid.
 */
export function verifyBrassV2(input, opts = {}) {
  const fail = error => ({
    valid: false,
    error,
    format: "voprf-token",
    algorithm: input?.algorithm || "voprf-p256-sha256",
  });
  if (!input || input.protocol !== "BRASS" || input.version !== "2.0") return fail("not_brass_v2");
  if (!opts.issuerPublicKey) return fail("issuer_key_pin_required");
  if (input.issuer_public_key !== opts.issuerPublicKey) return fail("issuer_key_mismatch");
  if (opts.expectedKid && input.kid !== opts.expectedKid) return fail("kid_mismatch");
  if (!input.piI?.c || !input.piI?.z || !input.piC?.c || !input.piC?.z) return fail("missing_proofs");

  try {
    const Y = decodePoint(input.issuer_public_key);
    const P = decodePoint(input.P);
    const M = decodePoint(input.M);
    const Z = decodePoint(input.Z);
    const Zprime = decodePoint(input.Zprime);
    if (!scopePoint(input.scope).equals(P)) return fail("scope_point_mismatch");
    if (!verifyDleq(G, Y, M, Z, input.piI, new Uint8Array(0))) return fail("invalid_piI");

    const eta = deriveEta(input);
    const bind = H3("BRASS:BIND:", input.c_nonce, input.d, eta, H3("no_exporter"));
    if (!verifyDleq(P, M, Zprime, Z, input.piC, bind)) return fail("invalid_piC");

    const nullifier = b64urlEncode(H3(
      "BRASS_NULLIFIER_v1",
      input.Zprime,
      input.kid,
      input.aadr || "",
      eta,
    ));
    return {
      valid: true,
      format: "voprf-token",
      algorithm: input.algorithm,
      scope: input.scope,
      nullifier,
      kid: input.kid,
      transport_hint: input.transport_hint || "local-selective-disclosure",
      dleq: { issuer: true, client: true },
      protocolVersion: "2.0",
    };
  } catch (error) {
    return fail(`invalid_proof:${error.message}`);
  }
}
