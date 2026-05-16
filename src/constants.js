/**
 * @veritasacta/verify: Single-source-of-truth constants
 *
 * Strings and identifiers that MUST stay byte-identical across the CLI,
 * the test-vectors generator, and any future conformance-test runner.
 * Importing from one place prevents docs/code drift from silently
 * desynchronizing rejection-path semantics.
 *
 * Add a new constant here when:
 *   - a fixture's `expected_result.error` should match the CLI's output
 *     verbatim, AND
 *   - the string is normatively pinned to a spec section (cite the
 *     normative reference in the JSDoc comment).
 */

/**
 * Rejection error: APS verification key transported inside the receipt
 * envelope without an independent anchor (sidecar JWKS, DID resolution,
 * or other independently anchored key reference).
 *
 * Pinned to draft-farley-acta-signed-receipts-02 Security Considerations.
 *
 * Used by:
 *   - test-vectors/generate.mjs → cross-verify-embedded-key-bundle.json
 *     `expected_result.error` and `expected_verification.error`
 *   - src/verifier.js (forthcoming v0.7+ enforcement landing) → emitted
 *     when a bundle declares `external_receipts.aps.signing_key` without
 *     an accompanying `verification_key_ref`.
 */
export const REJECTION_ERROR_EMBEDDED_KEY =
  'verification key transported inside receipt without independent anchor';
