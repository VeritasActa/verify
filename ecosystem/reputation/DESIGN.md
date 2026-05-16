# Issuer Reputation Layer (v0.7.0 target)

Bayesian reputation over RECEIPT ISSUERS (not agents — aeoess already
has agent reputation; this complements it with the inverse).

## Goal

Track which issuer keys reliably produce valid, well-formed,
conformance-tier-appropriate receipts. Give verifiers an additional
signal — not a replacement for cryptographic verification, but a
reliability metric that composes with it.

## Axes

Per issuer key (kid), track:

- **Conformance rate** — fraction of receipts that pass full
  verification
- **Chain integrity rate** — fraction of chains that verify without
  breakage
- **Tier distribution** — which conformance tiers the issuer reaches
- **Receipt frequency** — issuance rate over time
- **Jurisdictional distribution** — where receipts are verified

## Data source

Optional: the verifier daemon can contribute anonymized observations
to a public reputation log (opt-in). Or: organizations run private
reputation logs for their own issuer pools.

No phone-home by default. Reputation is computed locally or on explicit
public submission.

## Composition with aeoess APS

- aeoess reputation = on agents / principals ("can we trust agent X to
  act?")
- Veritas Acta reputation = on issuers / signers ("does issuer Y
  reliably produce valid receipts?")

Together they cover both sides of the trust surface.

## Non-goals

- Not a proof of trustworthiness (only evidence of historical
  reliability)
- Not a replacement for signature verification
- Not a ranking / leaderboard (raw metrics, not ordinal)

## License

Apache-2.0 once shipped.
