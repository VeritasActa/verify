# Conformance Certification — Commercial Service Design

Draft spec for a commercial conformance certification service. Not an
open-source artifact; this document is internal product spec for the
ScopeBlind managed tier.

## Problem

Enterprise and regulated-industry buyers increasingly ask "is this
implementation verified?" Self-certification via the open conformance
test suite is acceptable for most; some buyers require independent
certification.

## Service outline

**Customer:** an implementer (or consumer of an implementation) who
needs formal third-party attestation that a specific release of an
implementation passes conformance.

**Workflow:**

1. Customer submits an implementation release (artifact hash + repo
   link) for certification.
2. ScopeBlind runs the full conformance suite, including negative
   vectors, against the submitted release.
3. ScopeBlind manually reviews: dependency tree, threat model, test
   coverage, cryptographic correctness spot-checks, build
   reproducibility.
4. ScopeBlind issues a signed "Conformance Certification" attestation
   valid for 12 months, naming the implementation, tier, and review
   summary.
5. Certification is anchored in the public registry with a link to
   the signed attestation (the attestation itself remains with the
   customer; only the hash is public).

## Certification attestation format

```json
{
  "type": "veritasacta:conformance-certification",
  "spec": "draft-farley-acta-signed-receipts-03",
  "certified_implementation": {
    "name": "acme-runtime",
    "repo": "https://github.com/acme/acme-runtime",
    "version": "1.2.0",
    "artifact_hash": "sha256:abc123...",
    "claimed_tier": 4
  },
  "certification": {
    "tier_verified": 4,
    "review_summary": "ACTA-CC-2026-0008",
    "review_methodology": "Full conformance suite + manual cryptographic spot-check + dependency audit + threat model review",
    "issued_at": "2026-07-15T12:00:00.000Z",
    "expires_at": "2027-07-15T12:00:00.000Z",
    "issuing_authority": "ScopeBlind (Veritas Acta)"
  },
  "signature": {
    "alg": "EdDSA",
    "kid": "scopeblind:certification:2026-q3",
    "sig": "<Ed25519 signature>"
  }
}
```

## Pricing (draft)

| Tier | Scope | Duration | Price (AUD) |
|---|---|---|---|
| Single release | One version of one implementation | 12 months | $2,000 |
| Release train | Four versions over 12 months (auto-renewing) | 12 months | $6,000 |
| Enterprise | Up to 10 implementations, rolling certifications | 12 months | $25,000 |
| Custom | Specific jurisdictions / regulations (HIPAA, FedRAMP) | Negotiable | From $15,000 |

Pricing is anchored to comparable certification markets (SOC 2 Type II
audits from $25K, FIPS 140-3 validation from $50K). Veritas Acta
certification is positioned as cheaper, faster, and more focused than
those but backed by the specific implementation test suite rather than
general security posture.

## Delivery SLA

- **Single release:** 5 business days review, written summary within 10
  business days.
- **Expedited review (+50% fee):** 2 business days.
- **Enterprise tier:** named contact, quarterly review summary.

## Marketing positioning

- Certified implementations earn a "Certified by Veritas Acta"
  registry entry with a distinctive badge.
- Public announcement via a monthly "Certified This Month" blog post.
- Joint case study opportunity for flagship certifications.

## Operational requirements

- Dedicated attester key (air-gapped HSM) for certification
  signatures
- Auditor team (initially 1-2 people; scale with demand)
- Published methodology document and versioned test suite
- Semi-annual methodology review + public changelog

## Dependencies for GA

- v0.5.0 shipped (✓)
- Registry worker deployed (in progress; scaffold in
  `ecosystem/registry-worker/`)
- Badge service deployed (in progress; scaffold in
  `ecosystem/badge-worker/`)
- Methodology doc published
- First-customer pilot (target: Q3 2026)

## Not-yet-decided

- Whether certifications appear in a Rekor-style transparency log
- Whether certification revocation events are published publicly
- Whether multi-tier certifications (e.g., T4 + specific FIPS
  variants) require separate pricing
