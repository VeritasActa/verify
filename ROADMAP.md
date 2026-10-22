# Maintenance priorities and status

This page describes the current project boundary and possible next work. It is
not a delivery schedule. Exact shipped changes are in [CHANGELOG.md](CHANGELOG.md);
the current release and standards status are in
[release-manifest.json](release-manifest.json).

## Maintained release surface

- The CLI, its shipped verification profiles and the shared browser receipt engine.
- Explicit verified, failed and not-checked outcomes, with independent key input
  for the Acta receipt and audit-bundle paths. Specialist profiles have their own
  limitations; see the [README](README.md) and [reference](docs/reference.md).
- Regression tests, packed-install checks, the browser build and the bundled
  integrity commitment. The commitment alone does not authenticate the publisher.
- A pinned comparison with [TRACE's Acta fixtures](docs/trace-fixtures.md): 11
  fixtures and 35 checks. Policy freshness and session binding are not compared.

The 0.10.x release history supersedes the old 0.5–0.9 plans on this page. Missing-key
classification, declared crypto dependencies and chain-link corrections are
already implemented; they are not outstanding roadmap commitments.

## Useful next work

1. Expand reproducible compatibility fixtures from independently maintained
   implementations, with explicit negative and unsupported cases.
2. Improve clean-install documentation and profile-specific trust-boundary examples.
3. Review legacy and specialist paths against the current outcome semantics before
   expanding what a successful result promises.

An independent-verifier matrix is **planned work** in the separate
[conformance project](https://github.com/ScopeBlind/agent-governance-testvectors).
Multiple producers checked by this verifier are not equivalent to multiple
independent verifiers agreeing. No grant award or delivery date is implied here.

## Compatibility and optional integrations

The CLI still parses `--allow-embedded-key` and `--allow-partial-voprf`. Their effect
depends on the profile; parsing a legacy flag does not establish that an embedded
key or a partial proof is acceptable. Use an independently supplied key and read
the reported checks. Any removal or behavior change should be documented in release
notes with migration guidance, rather than inferred from an old planned date.

The [ecosystem directory](https://github.com/VeritasActa/verify/tree/main/ecosystem) contains historical adapters,
examples and design proposals. Their presence does not establish a published,
deployed or release-tested integration. New production integrations need their own
maintainer, current format fixtures and clean-install verification.

Propose a bounded contribution through [CONTRIBUTING.md](CONTRIBUTING.md). Decisions
and release authority are described in [GOVERNANCE.md](GOVERNANCE.md).
