# Security Policy

## Supported Versions

| Version | Status         | Support through |
|---------|----------------|-----------------|
| 0.5.x   | Current        | Next major      |
| 0.4.x   | Security only  | 2026-10-19      |
| 0.3.x   | End of life    | ended 2026-04-19|
| < 0.3   | End of life    | —               |

Receipts verified with an EOL version should be re-verified with a
current version to confirm continued validity.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in
`@veritasacta/verify`, please report it privately.

**Email:** security@scopeblind.com

**Response time:**
- Acknowledgment within 48 hours
- Initial assessment within 5 business days
- Coordinated disclosure target: 90 days (shorter for actively
  exploited issues, longer for complex issues requiring upstream fixes)

**What to include:**
- Version affected
- A clear description of the issue
- Reproduction steps (if applicable)
- Suggested remediation (if you have one)
- Whether you intend to publish (we can coordinate disclosure timing)

**What we will do:**
- Acknowledge your report
- Assess severity and impact
- Develop and test a fix
- Coordinate disclosure with you
- Credit you in the release notes unless you prefer otherwise

## Scope

### In scope

- Cryptographic verification correctness bugs in the verifier
- Canonicalization divergence from RFC 8785 / AIP-0001
- Supply chain risks in the published package
- Side-channel attacks against the verification path (e.g., timing)
- Algorithm downgrade or silent fallback behavior
- Self-check bypass (Sigil commitment verification)

### Out of scope

- Bugs in dependencies (report to upstream: @noble/curves, @noble/hashes)
- Threat-model non-goals documented in THREAT-MODEL.md (e.g.,
  compromised signing keys, issuer collusion, policy semantics)
- Usage errors unrelated to verification correctness
- Social engineering against the ScopeBlind team

## Coordinated Disclosure Examples

- **Embedded-key acceptance (fixed in 0.4.0):** surfaced publicly by
  @desiorac on GetBindu PR #459 before reaching us privately. We
  accept that publication of the issue on a third-party project was
  legitimate; we responded with 0.4.0 within one week.
- We prefer private disclosure, but we will not penalize researchers
  who choose to disclose publicly; our goal is correct verification,
  not reporter punishment.

## Hall of Fame

Security researchers who have helped improve @veritasacta/verify:

- @desiorac — embedded-key rejection (surfaced on GetBindu #459,
  landed in 0.4.0)

## Supply Chain

Each release is published with:

- `npm publish --provenance` — Sigstore-attested supply chain
- Sigil commitment in `sigil.json` covering all source files
- GPG-signed git tag (when the release workflow runs)

Verify the integrity of your installation:

```bash
# Verify npm provenance
npm audit signatures

# Verify local files match the Sigil
npx @veritasacta/verify --self-check
```

Cross-check the expected Sigil fingerprint against the canonical
release published on https://veritasacta.com.
