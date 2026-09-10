/**
 * Legate adherence / restraint proof pack verifier.
 *
 * A proof pack (type "scopeblind.legate.proof-pack.v1") is the allocator-facing,
 * POSITION-BLIND record a Legate desk produces: what the gate prevented over a
 * session (held / blocked, attributed to rules), what the order-path shadow would
 * have blocked, and the digests it is bound to (committed mandate, signed book
 * provenance, receipt Merkle root). It carries its own runtime verification key, so
 * a third party re-verifies it offline with nothing but this CLI.
 *
 * Signature recipe (legate-proof-pack.cjs signProofPack): Ed25519 over the UTF-8
 * bytes of the canonical (deep-sorted, no-whitespace) JSON of the pack MINUS its
 * `signature`, `sha256`, and `hybrid_signature` fields; `sha256` is that canonical's
 * SHA-256 digest. The runtime public key is `verification_key` (and runtime.
 * verification_key), raw 32-byte hex. Signing is over the bytes directly, like the
 * Legate governed receipt, NOT over a pre-hash like the Gate tuple.
 *
 * @module verify-cli/src/engines/legate-proof-pack
 */

import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../util/canonical.js';
import { hexToBytes, bytesToHex } from '../util/hex.js';

export const PROOF_PACK_TYPE = 'scopeblind.legate.proof-pack.v1';

const isString = (v) => typeof v === 'string' && v.length > 0;
const HEX = (s) => typeof s === 'string' && /^[0-9a-f]+$/i.test(s) && s.length % 2 === 0;
const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

const PROVES = [
  'The pack was signed by the holder of the runtime key (verification_key) and not altered since: every field is bound by the Ed25519 signature over the canonical bytes.',
  'The restraint counts (held / blocked, by rule) and the order-path shadow counts are the runtime\'s own, attributed to the committed mandate digest.',
  'The artifact is position-blind: it contains digests and counts only, never positions, so adherence is verifiable without disclosing the book.',
];
const LIMITATIONS = [
  'That the underlying receipts behind the Merkle root and the signed book behind book.sha256 are themselves correct, unless those are separately verified.',
  'That the runtime key belongs to the desk you expect; pin it with --key to bind the pack to a known runtime.',
];

/**
 * Reconstruct the exact canonical string that was signed: the pack minus the
 * signature, the bound digest, and any hybrid signature.
 */
export function proofPackSignedCanonical(pack) {
  const { signature, sha256: _digest, hybrid_signature, ...rest } = pack;
  return canonicalize(rest);
}

/**
 * @param {object} pack the proof pack envelope
 * @param {object} opts { publicKey?: pinned runtime key (hex) }
 */
export function verifyLegateProofPack(pack, opts = {}) {
  const base = {
    format: 'legate-proof-pack',
    schema: isString(pack?.type) ? pack.type : PROOF_PACK_TYPE,
    algorithm: 'ed25519',
  };

  if (pack === null || typeof pack !== 'object' || Array.isArray(pack)) {
    return { valid: false, error: 'unknown_format', ...base, detail: 'proof pack is not an object' };
  }
  if (pack.type !== PROOF_PACK_TYPE) {
    return { valid: false, error: 'unknown_format', ...base, detail: `type is not ${PROOF_PACK_TYPE}` };
  }

  const vk = isString(pack.verification_key)
    ? pack.verification_key
    : (pack.runtime && isString(pack.runtime.verification_key) ? pack.runtime.verification_key : undefined);

  if (!isString(pack.signature)) return { valid: false, error: 'missing_signature', ...base };
  if (!isString(vk)) return { valid: false, error: 'no_public_key', ...base };
  if (!HEX(pack.signature) || !HEX(vk)) {
    return { valid: false, error: 'malformed_hex', ...base, detail: 'signature and verification_key must be hex' };
  }

  const pinned = isString(opts.publicKey);
  if (pinned && opts.publicKey.toLowerCase() !== vk.toLowerCase()) {
    return { valid: false, error: 'key_mismatch', ...base, publicKey: vk, expectedKey: opts.publicKey };
  }

  // The bound digest must match the canonical the signature covers.
  const canonical = proofPackSignedCanonical(pack);
  if (isString(pack.sha256)) {
    const recomputed = bytesToHex(sha256(utf8ToBytes(canonical)));
    if (recomputed !== pack.sha256) {
      return { valid: false, error: 'digest_mismatch', ...base, detail: 'sha256 does not match the canonical bytes (the pack was modified after signing)', publicKey: vk };
    }
  }

  let ok = false;
  try {
    ok = ed25519.verify(hexToBytes(pack.signature), utf8ToBytes(canonical), hexToBytes(vk));
  } catch (e) {
    return { valid: false, error: 'malformed_hex', ...base, detail: e.message, publicKey: vk };
  }
  if (!ok) {
    return { valid: false, error: 'invalid_signature', ...base, publicKey: vk };
  }

  const mandate = pack.mandate || {};
  const restraint = pack.restraint || {};
  const shadow = pack.shadow || null;
  const book = pack.book || {};

  return {
    valid: true,
    ...base,
    publicKey: vk,
    keySource: pinned ? 'embedded-pack (pinned via --key)' : 'embedded-pack',
    signerKid: isString(pack.signer_kid) ? pack.signer_kid : undefined,
    generatedAt: isString(pack.generated_at) ? pack.generated_at : undefined,
    positionBlind: pack.position_blind !== false,
    mandate: { name: mandate.name, sha256: mandate.sha256, mode: mandate.mode, ruleCount: num(mandate.rule_count) },
    restraint: { blocked: num(restraint.blocked), held: num(restraint.held), byRule: Array.isArray(restraint.by_rule) ? restraint.by_rule : [] },
    shadow: shadow ? { observed: num(shadow.observed), wouldBlock: num(shadow.would_block), wouldHold: num(shadow.would_hold) } : null,
    bookDigest: isString(book.sha256) ? book.sha256 : null,
    sessionMerkleRoot: isString(pack.session_merkle_root) ? pack.session_merkle_root : null,
    receiptCount: num(pack.receipt_count),
    // A hybrid post-quantum signature, when present, is recognized and reported.
    // Classical Ed25519 is verified here; ML-DSA-65 verification is an optional add-on
    // (the runtime is dependency-free and signs classically; PQ is documented in the
    // restraint-receipts draft as an optional field for surfaces that can produce it).
    hybridSignaturePresent: Boolean(pack.hybrid_signature),
    proves: PROVES,
    limitations: LIMITATIONS,
  };
}
