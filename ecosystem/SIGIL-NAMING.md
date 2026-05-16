# Veritas Acta Sigil Naming Convention

Every release of `@veritasacta/verify` receives a unique Sigil — a
visual cryptographic commitment to the binary. Each Sigil has a
deterministic name derived from its fingerprint.

## How names are generated

The `generate-sigil.mjs` script produces a Sigil after the source code
is frozen. It derives:

- A SHA-256 `sigil_hash` from `(project_public_key, policy_hash, nonce)`
- A `fingerprint` = first 8 hex characters of the sigil hash
- A `name` = two-word label derived from the fingerprint

Name derivation:

```
n = parseInt(fingerprint[0:4], 16)
m = parseInt(fingerprint[4:8], 16)
name = NAME_ADJ[n % 24] + " " + NAME_NOUN[m % 24]
```

The 24×24 = 576 possible names keep the namespace collision-averse
enough for ~100 releases. If a collision ever occurs, the older name
retains priority in public comms.

## Adjective pool (24)

Bright · Quiet · Deep · Bold · Pale · Warm · Still · Swift · Clear ·
Dark · First · True · Slow · Fair · Old · New · Gilded · Woven · Open ·
High · Lone · Kind · Keen · Wild

## Noun pool (24)

Ember · Harbor · Field · Beacon · River · Grove · Arrow · Stone ·
Ridge · Wind · Tide · Star · Vale · Peak · Lake · Dawn · Reed · Cairn ·
Orchard · Meadow · Hearth · Anchor · Vessel · Thread

## Why names matter (brand convention)

1. **Memorability.** "We're pinned to New Wind" is easier to reason
   about than "5247a989".
2. **Visibility.** Release announcements lead with the name. The
   fingerprint is the precise handle; the name is the social handle.
3. **Non-interchangeability.** A fork that produces its own Sigil gets
   a DIFFERENT name. Users can see at a glance whether the installed
   verifier is the canonical release.
4. **Longevity.** Names compose with version numbers: "Swift Wind
   0.5.0" vs "New Wind 0.5.0" signals which Sigil commitment is
   active.

## Historical Sigil registry

| Version | Sigil name | Fingerprint | Released | Notes |
|---|---|---|---|---|
| 0.3.0 | Slow Reed | dd0443f0 | 2026-04-13 | First Sigil-attested release |
| 0.4.0 | Slow Cairn | e6647ab1 | 2026-04-19 | Embedded-key rejection |
| 0.5.0 | (pending)  | (TBD)    | (pending) | Unified verifier |

Future releases add to this table as they ship. The canonical registry
lives at `https://veritasacta.com/sigils` once the badge service is
deployed.

## Related

- `packages/verify-cli/generate-sigil.mjs` — derivation code
- `packages/verify-cli/sigil.json` — current commitment
- `patents/filed/provisional-5/` — Sigil patent claims
