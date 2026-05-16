# Physical-Digital Causal Chains — Seal cost-tier T2 attestation

**Status:** Design spec (v0.7 target)
**Related:** AIP-0005 (Attestation Weight Profile), `memory/seal-hardware-strategy.md`

## Goal

Extend the signed decision receipt format so that receipts can claim
**T2 = hardware-attested** (per AIP-0005) when the signing key lives
inside a hardware secure element (ATECC608B, TA100, SE050, TPM2, SGX,
etc.) and a platform quote binds the key to that element.

This turns receipts from "a software process signed this" into "a
specific hardware element, whose key was provisioned under declared
procedure, signed this." That's the property cold-chain operators,
regulatory auditors, and insurance adjusters need.

## Why this matters

Software-only receipts can be forged by an attacker who steals the
signing key. No amount of cryptographic sophistication in the receipt
format can prevent key exfiltration from a compromised OS. T2
receipts raise the forgery cost from "compromise the OS" to "extract
a key from a tamper-resistant chip" — a 1000-2000x increase in
attacker cost (numbers from EAL certification bodies).

The Seal hardware program exists specifically to produce this kind of
evidence for physical events (temperature chains, shipping custody,
tamper seals). ScopeBlind's strategic position is that the same
receipt format handles both purely-digital decisions AND
physical-digital chains where some links came from a sensor.

## Architecture

### Receipt shape (additive over AIP-0001)

A T2-claiming receipt adds two fields to the existing payload:

```json
{
  "payload": {
    "type": "decision-receipt",
    "action": "physical.chain_of_custody.temperature_reading",
    "cost_tier": 2,
    "attestation_mode": "atecc608b" | "ta100" | "se050" | "tpm2" | "sgx",
    "attestation_quote": {
      "format": "atecc608b-signed-data-v1",
      "quote": "<base64url>",
      "measured_kid": "<should match signature.kid>",
      "provisioning_ca": "<x5c chain or fingerprint>"
    },
    ... existing AIP-0001 fields ...
  },
  "signature": { "alg": "ES256", "kid": "<same as measured_kid>", "sig": "..." }
}
```

`attestation_quote` is the vendor-specific platform attestation. For
ATECC608B (our Seal v1), it's the `Sign()` operation over a challenge
bound to the receipt payload hash, with the chip's `provisioner_cert`
chain. The verifier checks three things:

1. The chip's `provisioning_ca` is a trusted root (Microchip's CA, or
   our own provisioning CA for Seal v1).
2. The quote signs the receipt's canonical payload hash with
   `measured_kid`.
3. `signature.kid` equals `measured_kid` — the same key that signed
   the receipt also produced the platform quote.

### Sensor reading → decision receipt pipeline

```
┌─────────────────────────┐     ┌─────────────────────────┐
│ SHT40 sensor            │     │ ATECC608B secure element│
│  reads temp + humidity  │     │  holds ECDSA P-256 key  │
└────────────┬────────────┘     │  exports platform quote │
             │ I²C                │                         │
             ▼                   └─────────────┬───────────┘
┌────────────────────────────────────────────┐ │
│ nRF52840 MCU                               │ │
│  - constructs JCS receipt payload          │ │
│  - hashes payload                          │ │
│  - asks ATECC608B to sign + quote          │◄┘
│  - emits { payload, signature, quote }     │
└────────────┬───────────────────────────────┘
             │ BLE / NFC / LoRa
             ▼
  Phone / gateway / verifier (offline)
  validates signature + quote + cost_tier=T2
```

The sensor is NOT trusted; only the ATECC608B's signature is. What the
chip signs is whatever the firmware hands it. If the firmware is
compromised to misreport temperature, T2 doesn't save you — that's why
T2 is a property claim about the SIGNING, not about the truthfulness of
the data. Higher tiers (T3 multi-party, T4 transparency-anchored) add
additional cross-checks.

## Verifier requirements

A conformant verifier implementing this extension SHOULD:

1. When `cost_tier >= 2` is claimed, REQUIRE `attestation_mode` and
   `attestation_quote` fields.
2. Dispatch to a per-platform validator based on `attestation_mode`:
   - `atecc608b` → validate the Microchip provisioner chain + re-verify
     the chip's signature over the receipt hash.
   - `tpm2` → validate the TPM2 AK certificate + quote structure.
   - `sgx` / `sev-snp` / `tdx` → platform-specific quote verification.
3. If the platform is unknown, return `undecidable` (exit 2) rather
   than `invalid` (exit 1) — the receipt might be valid under a
   platform the verifier doesn't know.
4. If the platform is known but the quote fails, return `invalid`
   (exit 1) — this is a proven mismatch.

The verifier is NOT required to implement all platforms. A verifier
might implement TPM2 only and punt on ATECC608B. It just must clearly
report *why* it can't verify.

## Implementation path

### v0.5.2 (now, scaffold)

This spec + the `attestation_quote` field schema shipped under
`schemas/` + AIP-0005 tier mapping. No verifier code yet — the tier
is parseable but not validated.

### v0.6.0

Minimal validator for `attestation_mode: custom` that checks the
quote is a well-formed object with `format`, `quote`, and
`measured_kid`, and verifies `measured_kid == signature.kid`. That's
the "at least it's consistent" check. Full platform-specific
validators deferred.

### v0.7.0

One real platform validator — target is TPM2 because the quote
format is well-documented and reference libraries exist (tpm2-tss).
Second validator (ATECC608B, for Seal) added once the chip's
provisioning chain is formalised.

### v1.0+

All major secure element platforms: ATECC608B, TA100, SE050, TPM2,
SGX/SEV-SNP/TDX, SE embedded in ARM TrustZone phones.

## Relationship to Seal hardware program

Seal v1 ships with ATECC608B + ECDSA P-256. Every reading produces a
receipt whose `cost_tier = 2` and whose `attestation_mode =
atecc608b`. The quote is the chip's authenticated sign operation.
The `provisioning_ca` is a ScopeBlind-operated intermediate CA; when
Microchip certifies our provisioning, we'll also ship the Microchip
chain for cross-verification.

Before Seal ships, the T2 mechanism is still useful: any software
running on a TPM-backed server, an Apple device with Secure Enclave,
or a KMS-backed CloudHSM can claim T2 today. The receipt format
doesn't care; only the evidence matters.

## Non-goals

- Not a replacement for TEE attestation protocols. We don't reinvent
  TPM2 / SGX / SEV — we reference their quotes verbatim.
- Not a DRM mechanism. T2 says "a specific hardware element signed
  this." It doesn't prevent the holder from doing other things with
  the receipt.
- Not a hardware supply-chain proof. If the chip itself was
  adversarially backdoored, T2 can't detect that. Supply-chain
  provenance is a parallel problem; AIP-0005 tiers describe one
  property (cost to forge the signature), not every property.

## Open questions

1. How do we represent ATECC608B's non-standard signature format
   when the verifier needs a standard ECDSA verification path?
   (Current plan: firmware emits the raw `r` + `s` and the verifier
   wraps them in DER at receive time.)
2. For Seal, do we ship our own provisioning CA publicly or gate it
   behind a trust-anchor file operators import? (Current plan:
   publicly published + trust-anchor-file optional for private
   deployments.)
3. Should the verifier treat unknown platforms as an error or
   silently downgrade the tier to T0? The spec says `undecidable`
   (exit 2). An alternative is "accept the receipt but surface the
   tier as T0 because we couldn't validate T2." This is a UX
   question, not a security question.

## Reference implementation sketch

Until v0.6.0 ships the validator, the schema below is the interface.

```typescript
interface AttestationQuote {
  /** Vendor-specific format identifier. */
  format: string;
  /** Raw quote bytes, base64url-encoded. */
  quote: string;
  /** Key identifier that MUST match the receipt's signature.kid. */
  measured_kid: string;
  /** Provisioning CA chain (X.509 x5c) or fingerprint list. */
  provisioning_ca?: string | string[];
  /** Reference values (PCRs, IMA hashes, etc.) the operator expects. */
  reference_values?: Record<string, string>;
}
```

## License

Apache-2.0 when shipped.
