# Security Policy

## Supported Versions

Security fixes target the latest published release. Older patch releases and
previous minor lines are not separately maintained; upgrade before relying on
their verification results. There is no long-term support commitment.

The current version is recorded in [release-manifest.json](release-manifest.json)
and its changes in [CHANGELOG.md](CHANGELOG.md). If a fix affects a profile you use,
re-verify relevant receipts with the fixed release. A historical verification
result does not establish that a later-discovered bug was absent.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in
`@veritasacta/verify`, please report it privately.

**Email:** security@scopeblind.com

**Response targets** (a maintainer-run project, not a response-time guarantee):
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

- Dependency issues that do not affect this verifier (report to the relevant
  upstream project). Please report affected verification or package paths here
  as well so we can assess impact and update dependencies.
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

- @desiorac: embedded-key rejection (surfaced on GetBindu #459,
  landed in 0.4.0)

## Supply Chain

The current [release workflow](https://github.com/VeritasActa/verify/blob/main/.github/workflows/publish.yml) publishes from
`main` through the npm environment, using npm trusted publishing and
`--provenance`. It tests and packs the source, then checks a clean installation
before publishing that tarball. The 0.10.27 npm release has provenance. Do not
assume that every historical release has it; inspect the exact version you use.

The release also includes a Sigil commitment in `sigil.json` covering `cli.js`,
every shipped executable JavaScript module under `src/`, and the other explicitly
declared monitored sources. This is a recomputable integrity commitment, not a
publisher signature.

Git release tags are not guaranteed to be signed. In particular, `v0.10.27` is a
lightweight tag pointing to a signed commit; a signed commit is not a signed tag.
The publish workflow does not create or sign tags.

Verify the integrity of your installation:

```bash
# In a project that installed the package, check registry signatures/attestations
npm audit signatures

# Verify local files match the Sigil
verify --self-check
```

Obtain the expected Sigil fingerprint through an independently authenticated
channel, then pass it to `--pin-sigil`. A self-check without an independently
pinned fingerprint is only a local comparison with the bundled commitment; it
does not authenticate the package publisher.
