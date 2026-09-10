/**
 * EAT output mode (packaging sprint A4).
 *
 * Re-serializes a verified Veritas Acta / Legate receipt as an RFC 9711 EAT
 * (Entity Attestation Token) claims-set, so a Legate receipt is ALSO a valid
 * EAT/TRACE record that EAT-aware tooling can ingest. Two serializations:
 *   - JSON: CWT/EAT claim NAMES (RFC 8392 JSON mapping), human-readable.
 *   - CBOR: CWT claim KEYS (integers), the canonical EAT/CWT wire form.
 *
 * Honest boundary: this maps and re-serializes an already-Ed25519-signed
 * receipt; it does NOT mint a fresh COSE_Sign1 (that requires the issuer key,
 * which the offline verifier does not hold). Authenticity round-trips to the
 * embedded Acta receipt and its signature, which the verifier already checked.
 * A hardware attestation quote, if the receipt carries one, is passed through
 * verbatim as the EAT `submods`/`tee_evidence` claim (carry, do not appraise).
 */

// ── CWT / EAT claim keys (IANA CWT registry; RFC 8392 + RFC 9711) ────────────
const CWT_ISS = 1;
const CWT_SUB = 2;
const CWT_IAT = 6;
const CWT_CTI = 7;
const EAT_NONCE = 10;
const EAT_PROFILE = 265;
const EAT_MEASUREMENTS = 273;
// Private-use claim keys (negative ints are reserved for private use, RFC 8392).
const PRIV_ACTA_RECEIPT = -70000; // the full original Acta receipt (canonical JSON)
const PRIV_VERIFICATION = -70001; // the offline verification summary
const PRIV_TEE_EVIDENCE = -70002; // a carried hardware attestation quote, verbatim

const EAT_PROFILE_URI = 'https://veritasacta.com/eat-profile/legate-receipt/v1';

// Governed/gate receipts nest their action fields under `payload`; look there too.
function f(receipt, name) {
  const v = receipt[name];
  if (v !== undefined && v !== null) return v;
  return receipt.payload ? receipt.payload[name] : undefined;
}

function iatFrom(receipt) {
  const s = f(receipt, 'signed_at') || f(receipt, 'at') || f(receipt, 'timestamp') || f(receipt, 'issued_at') || f(receipt, 'created_at');
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : Math.floor(t / 1000);
}

function subjectFrom(receipt) {
  return f(receipt, 'tool') || f(receipt, 'action') || f(receipt, 'action_id') || f(receipt, 'summary') || f(receipt, 'id') || null;
}

function ctiFrom(receipt) {
  return f(receipt, 'id') || f(receipt, 'receipt_id') || f(receipt, 'cti') || null;
}

function issuerFrom(receipt) {
  return receipt.verification_key || f(receipt, 'signer') || f(receipt, 'issuer') || null;
}

function teeEvidenceFrom(receipt) {
  return f(receipt, 'tee_evidence') || f(receipt, 'attestation') || f(receipt, 'attestation_quote') || null;
}

function measurementsFrom(receipt) {
  const m = {};
  const inp = f(receipt, 'input_sha256');
  const res = f(receipt, 'result_sha256');
  const pol = f(receipt, 'policy_sha256');
  const cfr = f(receipt, 'committed_fields_root');
  if (inp) m.input_sha256 = inp;
  if (res) m.result_sha256 = res;
  if (pol) m.policy_sha256 = pol;
  if (cfr) m.committed_fields_root = cfr;
  return Object.keys(m).length ? m : null;
}

function verificationSummary(result) {
  return {
    valid: result?.valid === true,
    format: result?.format ?? result?.modeLabel ?? null,
    signer: result?.signer ?? result?.publicKey ?? null,
    error: result?.error ?? null,
  };
}

/** Build the EAT claims-set with JSON claim NAMES. */
export function toEatClaims(receipt, result) {
  const claims = { eat_profile: EAT_PROFILE_URI };
  const iss = issuerFrom(receipt);
  if (iss) claims.iss = iss;
  const sub = subjectFrom(receipt);
  if (sub) claims.sub = sub;
  const iat = iatFrom(receipt);
  if (iat != null) claims.iat = iat;
  const cti = ctiFrom(receipt);
  if (cti) claims.cti = cti;
  if (receipt.nonce || receipt.eat_nonce) claims.eat_nonce = receipt.nonce || receipt.eat_nonce;
  const meas = measurementsFrom(receipt);
  if (meas) claims.measurements = meas;
  const tee = teeEvidenceFrom(receipt);
  if (tee) claims.tee_evidence = tee;
  claims.verification = verificationSummary(result);
  claims.acta_receipt = receipt; // full receipt, preserving its Ed25519 signature
  return claims;
}

export function emitEatJson(receipt, result) {
  return JSON.stringify(toEatClaims(receipt, result), null, 2);
}

// ── Minimal deterministic CBOR (RFC 8949 core, definite-length, sorted maps) ─
function cborHead(major, n) {
  const mt = major << 5;
  if (n < 24) return Uint8Array.of(mt | n);
  if (n < 0x100) return Uint8Array.of(mt | 24, n);
  if (n < 0x10000) return Uint8Array.of(mt | 25, n >> 8, n & 0xff);
  if (n < 0x100000000) return Uint8Array.of(mt | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  // 64-bit length (major 27); split into two 32-bit halves.
  const hi = Math.floor(n / 0x100000000);
  const lo = n >>> 0;
  return Uint8Array.of(mt | 27, (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff, (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);
}

function concatBytes(arrs) {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

/** Encode a value to deterministic CBOR. Supports the JSON value set + integers. */
export function cborEncode(value) {
  if (value === null || value === undefined) return Uint8Array.of(0xf6); // null
  if (value === true) return Uint8Array.of(0xf5);
  if (value === false) return Uint8Array.of(0xf4);
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      // Avoid float ambiguity: carry non-integers as their JSON text.
      return cborEncode(String(value));
    }
    return value >= 0 ? cborHead(0, value) : cborHead(1, -value - 1);
  }
  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    return concatBytes([cborHead(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) {
    return concatBytes([cborHead(2, value.length), value]);
  }
  if (Array.isArray(value)) {
    return concatBytes([cborHead(4, value.length), ...value.map(cborEncode)]);
  }
  if (typeof value === 'object') {
    // Map: encode each entry, sort by encoded-key bytes (RFC 8949 §4.2.1).
    const entries = [];
    for (const [k, v] of Object.entries(value)) {
      if (v === undefined) continue;
      // Numeric-looking keys carried as integers (used for CWT claim keys).
      const keyEnc = /^-?\d+$/.test(k) ? cborEncode(parseInt(k, 10)) : cborEncode(k);
      entries.push([keyEnc, cborEncode(v)]);
    }
    entries.sort((a, b) => {
      const x = a[0], y = b[0];
      const n = Math.min(x.length, y.length);
      for (let i = 0; i < n; i++) if (x[i] !== y[i]) return x[i] - y[i];
      return x.length - y.length;
    });
    return concatBytes([cborHead(5, entries.length), ...entries.flatMap((e) => e)]);
  }
  throw new Error(`cborEncode: unsupported type ${typeof value}`);
}

/** Build the CWT/EAT claims-set keyed by integer claim keys, for CBOR. */
export function toEatClaimsCbor(receipt, result) {
  const m = {};
  m[EAT_PROFILE] = EAT_PROFILE_URI;
  const iss = issuerFrom(receipt);
  if (iss) m[CWT_ISS] = iss;
  const sub = subjectFrom(receipt);
  if (sub) m[CWT_SUB] = sub;
  const iat = iatFrom(receipt);
  if (iat != null) m[CWT_IAT] = iat;
  const cti = ctiFrom(receipt);
  if (cti) m[CWT_CTI] = new TextEncoder().encode(String(cti)); // CWT cti is a byte string
  if (receipt.nonce || receipt.eat_nonce) m[EAT_NONCE] = String(receipt.nonce || receipt.eat_nonce);
  const meas = measurementsFrom(receipt);
  if (meas) m[EAT_MEASUREMENTS] = JSON.stringify(meas);
  const tee = teeEvidenceFrom(receipt);
  if (tee) m[PRIV_TEE_EVIDENCE] = JSON.stringify(tee);
  m[PRIV_VERIFICATION] = JSON.stringify(verificationSummary(result));
  // Carry the full receipt as canonical JSON text to preserve its exact bytes
  // (and its Ed25519 signature) without float-encoding ambiguity.
  m[PRIV_ACTA_RECEIPT] = JSON.stringify(receipt);
  return m;
}

/** Hex-encoded CBOR CWT/EAT claims-set. */
export function emitEatCbor(receipt, result) {
  const bytes = cborEncode(toEatClaimsCbor(receipt, result));
  return Buffer.from(bytes).toString('hex');
}
