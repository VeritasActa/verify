# Sigil Release Naming System

Every release of `@veritasacta/verify` gets a unique Sigil with a
deterministic name derived from its cryptographic fingerprint. The name
is not chosen — it emerges from the release's own content.

## How names are generated

When `generate-sigil.mjs` produces a Sigil, it:

1. Computes `sigil_hash = sha256("scopeblind:sigil:v2" || pubkey || policy_hash || nonce)`
2. Takes `fingerprint = first 8 hex chars of sigil_hash`
3. Parses `n = int(fingerprint[0:4], 16)`, `m = int(fingerprint[4:8], 16)`
4. Selects `name = ADJECTIVE[n % 24] + " " + NOUN[m % 24]`

This is **deterministic** — two verifier binaries with the same source
hash and the same project key produce the same Sigil, same fingerprint,
same name.

## Why release names matter (brand mechanism)

1. **Memorable.** "We pinned to Swift Wind" is easier than "pinned to
   Sigil fingerprint 87727f4b."
2. **Visible in release notes.** Every announcement leads with the name.
3. **Counterfeit detection.** A fork produces a DIFFERENT Sigil →
   different name. Users see at a glance.
4. **Marketing contagion.** Release names become conversational shorthand.

## Pool

24 adjectives × 24 nouns = 576 unique name combinations. Collision-averse
for ~100 releases; rare collisions can be disambiguated by version.

### Adjectives

Bright · Quiet · Deep · Bold · Pale · Warm · Still · Swift · Clear ·
Dark · First · True · Slow · Fair · Old · New · Gilded · Woven · Open ·
High · Lone · Kind · Keen · Wild

### Nouns

Ember · Harbor · Field · Beacon · River · Grove · Arrow · Stone ·
Ridge · Wind · Tide · Star · Vale · Peak · Lake · Dawn · Reed · Cairn ·
Orchard · Meadow · Hearth · Anchor · Vessel · Thread

## Historical Sigil registry

| Version | Sigil name | Fingerprint | Released | Highlight |
|---|---|---|---|---|
| 0.3.0 | Slow Reed | `dd0443f0` | 2026-04-13 | First Sigil-attested release |
| 0.4.0 | Slow Cairn | `e6647ab1` | 2026-04-19 | Embedded-key rejection |
| 0.5.0 | (current) | (current) | 2026-04-19 | Unified verifier |

After each release, this table is updated. The canonical live registry
is at `https://veritasacta.com/sigils`.

## Marketing cadence

- **Release announcement**: leads with the Sigil name. "Swift Wind is
  live."
- **Monthly "Sigil of the Month" blog post**: features the current
  release, technical changes, and a case study from any org that
  canonically attested that version.
- **Merchandise**: T-shirts, stickers, print art — each release can
  generate its own limited-edition asset. Optional but reinforces
  identity.

## Naming collisions

If two versions produce the same name (expected ~1 per 24 releases on
average), disambiguate by version number: "Swift Wind 0.5.0" vs. "Swift
Wind 0.7.0". Named Sigils are still cryptographically distinct via
fingerprint.

## Related

- `ecosystem/SIGIL-NAMING.md` — this file
- `generate-sigil.mjs` — derivation code
- `src/engines/sigil.js` — runtime verification
- Patent provisional #5 — Sigil visual commitment
