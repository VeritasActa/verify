# Veritas Acta Verify — GitHub Action

Verify signed decision receipts, VOPRF tokens, or Knowledge Units in any CI workflow. Installs `@veritasacta/verify`, confirms the installed verifier is the canonical unmodified release via Sigil self-check, then verifies your receipts.

## Usage

```yaml
name: Verify receipts

on:
  push:
    branches: [main]
  pull_request:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: VeritasActa/verify-action@v1
        with:
          receipts-path: "./receipts/**/*.json"
          public-key: ${{ secrets.ED25519_PUBLIC_KEY }}
          required-tier: 4
          pin-sigil: 5247a989
          attest: true
          attest-org: "Acme Corp"
          audit-report: "./audit-report.html"
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `receipts-path` | yes | — | Glob of receipt files to verify |
| `public-key` | no | — | Ed25519 pubkey hex |
| `jwks-url` | no | — | JWKS endpoint URL |
| `required-tier` | no | — | Minimum conformance tier (1-5) |
| `pin-sigil` | no | — | Require a specific Sigil fingerprint |
| `strict` | no | `true` | Disable deprecated fallbacks |
| `audit-report` | no | — | Path to write HTML audit report |
| `verifier-version` | no | `latest` | Version of `@veritasacta/verify` to install |
| `attest` | no | `false` | Emit canonical attestation |
| `attest-org` | no | — | Org name in attestation |

## Outputs

| Output | Description |
|---|---|
| `total` | Total receipts inspected |
| `verified` | Successfully verified |
| `failed` | Failed verifications |
| `sigil-fingerprint` | Fingerprint of the canonical verifier used |
| `attestation` | Canonical attestation JSON (when `attest: true`) |

## What this action does

1. Installs `@veritasacta/verify` from npm (`--provenance` attested)
2. Runs `--self-check` to prove the installed verifier is canonical
3. If `pin-sigil` provided, confirms Sigil fingerprint matches exactly
4. Verifies each receipt matching `receipts-path`
5. Optionally emits an HTML audit report as a workflow artifact
6. Optionally emits a canonical attestation to workflow outputs

## License

Apache-2.0
