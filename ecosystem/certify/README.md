# Conformance Certification Program

**Automated, weekly, cross-implementation verification of every
receipt-format implementation in the Veritas Acta ecosystem.**

This is the certification program that backs the
`veritasacta.com/certify` public badge — not prose, not self-
assertion, but continuously-run cross-verification evidence.

## What it does

Every Monday at 00:00 UTC, the workflow in [`workflows/run.yml`](./workflows/run.yml):

1. Checks out every registered implementation at the version they
   last self-declared (via the `agt-integration-profile` registry).
2. Generates 50 conformance-vector receipts per implementation,
   using a shared input corpus.
3. Cross-verifies each implementation's receipts against:
   - `@veritasacta/verify` (reference implementation)
   - `@veritasacta/cross-verify` (multi-format arbitrator)
4. Signs the aggregated results with a ScopeBlind certification key.
5. Publishes the signed result to `veritasacta.com/certify/<week>.json`.
6. Updates the live badge at `verify.veritasacta.com/badge/certify/<impl>`.

A green badge = "this implementation passed all conformance vectors
against the reference verifier within the last 7 days." A red badge
= "something regressed; see the signed result JSON for which vector
broke."

## What's certified

A conformance certification is specific to:

- **Implementation** (Signet, Hermes, protect-mcp, sb-runtime, …)
- **Version** (as declared by the implementation's maintainers)
- **AIP set** (which AIPs the implementation claims to support)

An implementation is considered "conformant at level L" when it passes
every conformance vector tagged at or below level L. Levels:

- **T1 Basic** — Ed25519 signature + JCS canonicalization + chain
  linkage
- **T2 Disclosure** — T1 + AIP-0002 selective-disclosure commitments
- **T3 Attestation** — T2 + AIP-0003 holder binding + attestation_mode
- **T4 Privacy** — T3 + VOPRF (full dual-DLEQ) + AIP-0005 cost_tier
- **T5 Full** — T4 + AIP-0006 delegation + AIP-0007 ZK compliance

## Why this is a moat

The certification program produces three outputs that no individual
implementation can produce alone:

1. **A signed agreement fingerprint.** Every certified implementation
   commits to a SHA-256 over the agreed conformance-vector results.
   Tampering with the certification data is cryptographically visible.
2. **A cross-implementation reachability graph.** We publish which
   pairs of implementations have been demonstrated to interoperate
   on which AIPs. Buyers choose implementations partly based on this
   graph.
3. **Temporal trust.** "Conformant as of 2026-04-20" is a stronger
   statement than "conformant" — it tells customers the certification
   is live, not stale.

## How to register an implementation

Open a PR against
[ScopeBlind/agt-integration-profile](https://github.com/ScopeBlind/agt-integration-profile)
with:

1. A `profile.yaml` describing your implementation, version, and
   claimed AIP support.
2. A pointer to your implementation's receipt-generation script (how
   to produce receipts given our shared conformance vectors).
3. A signing key the certification program can use to identify the
   implementation's output.

The weekly workflow picks up new registrations automatically.

## Certification vectors

`vectors/` contains the shared conformance-vector corpus. 50 vectors
per AIP, covering:

- Happy paths (well-formed receipts that must verify)
- Negative vectors (malformed receipts that must NOT verify)
- Edge cases (empty payloads, boundary-length strings, nested
  structures, UTF-8 corners)

Implementations are required to pass 100% of vectors at the AIP level
they claim.

## Independence

This program is operated by ScopeBlind (the maintainer of the
reference implementation) but the vectors, workflow, and signed
results are all public and Apache-2.0 licensed. Any third party can
re-run the workflow, produce their own signed certification, and
publish it alongside ours. Cross-signed certifications (we + an
independent auditor both sign) are the long-term goal.

## Status

| Registration phase | Status |
|---|---|
| Workflow scaffolded | ✅ shipped v0.5.4 |
| Vector corpus v1 (T1 + T2) | 🚧 in progress |
| First weekly run | 🎯 Monday after v0.5.4 ships |
| Public badge live | 🎯 with first weekly run |
| Cross-signed certifications | 🎯 Q3 2026 |

## License

Apache-2.0.
