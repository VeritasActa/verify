# Roadmap

What shipped since the last roadmap, what is next, and what is deprecated.
Release history with the detail is in [CHANGELOG.md](./CHANGELOG.md).

## Shipped since 0.5.4

- **0.6.1** (May 2026): AIP-0007 zero-knowledge compliance proofs, draft; transparency-log anchoring engine (AIP-0005 T4).
- **0.7.0** (June 2026): restraint receipts, proving what was prevented, offline and position-blind; the release rule for execution evidence.
- **0.8.0** (June 2026): RFC 6962 transparency log for macro track records; macro-engine snapshots and track-record bundles.
- **0.9.0** (June 2026): Legate adherence and restraint proof packs.
- **0.9.3** (July 2026): the 0.9.1/0.9.2 line and this line reconciled into one tree; draft-02 receipts and chain links in `--replay-chain`.
- **0.9.4 to 0.9.6** (August to September 2026): the chain link is computed over the whole signed receipt and carries the `sha256:` prefix, as draft-farley-acta-signed-receipts-03 section 6.7 specifies; genesis receipts omit `previousReceiptHash`; extra positional arguments are an error rather than a silent drop; the bundled integrity commitment is regenerated as the last step of a release, after 0.9.4 shipped with a stale one.

## Next

- Report a missing verification key as UNVERIFIABLE (exit 2) rather than INVALID (exit 1); today a receipt with no resolvable key is reported as if its signature failed.
- Declare `@noble/curves` where it is used so a clean install of the test suite does not depend on hoisting.
- Cite draft-farley-acta-signed-receipts-03 in every source comment that still names an earlier revision.
- Framework adapters: publish the ones people use or retire them from the README. `scopeblind-swarms` computes its chain link as base64url and must move to `sha256:` plus hex.
- Remove `--allow-embedded-key` and `--allow-partial-voprf` (see below).

## Deprecations

| Item | Deprecated in | Status at 0.9.6 |
|---|---|---|
| `--allow-embedded-key` | 0.4.0 | Still parsed, warns. Removal will be announced one minor release ahead. |
| `--allow-partial-voprf` | 0.5.0 | Still parsed, no-op since 0.5.0. Same removal rule. |
| `voprf-p256-sha256` v1 wire format (plain-concat hash) | 0.6.0 | Dual-mode; v1 still accepted. |

The removals planned for 0.6.0 and 0.7.0 did not happen. They will be done in
one release, announced in the CHANGELOG of the release before it.

## Commitments

- Every breaking change ships with a dual-mode transition window of at least one minor release.
- Every wire-format change is accompanied by conformance vectors in [ScopeBlind/agent-governance-testvectors](https://github.com/ScopeBlind/agent-governance-testvectors), where three independent implementations now verify against the same fixtures in CI.
- `--self-check` continues to compare the installed bytes with the bundled integrity commitment; a release whose commitment does not match its bytes is a defect (0.9.4 was one, fixed in 0.9.5).
