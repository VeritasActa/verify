# Veritas Acta Audit Dashboard (scaffold)

Local-first, offline audit dashboard for signed decision receipts.

Two static files — `index.html` + `dashboard.js` — that together render
receipt chains, surface tamper events, and generate SOC 2 / ISO 42001
/ EU AI Act summaries from JSON output of the unified verifier.

No server. No telemetry. Runs from a local `file://` URL, a local dev
server, or any static host (GitHub Pages, Cloudflare Pages, S3, etc.).

## How to use

Option A — direct file drop:

```bash
open index.html
```

Drag a folder of `*.json` receipts onto the drop zone. The dashboard
parses them in-browser, computes SHA-256 canonical hashes, checks
chain linkage, and renders a per-receipt table.

Option B — paste verifier output:

```bash
npx @veritasacta/verify --replay-chain receipts.jsonl --json > out.json
```

Paste the contents of `out.json` into the textarea. The dashboard
renders the already-verified results; cryptographic validation was
performed by the canonical verifier beforehand.

Option C — paste `verify compliance --json` output:

```bash
npx @veritasacta/verify compliance --receipts-dir ./audit \
    --framework all --json > compliance.json
```

Paste this to get framework-by-framework control coverage
visualization (v0.2 — not yet shipped in the scaffold).

## What it verifies

This scaffold performs **structural** verification only:

- JCS canonicalization of each receipt
- SHA-256 hash computation
- `previousReceiptHash` chain linkage validation

It does NOT verify Ed25519 signatures directly, because browsers
cannot parse arbitrary-encoded Ed25519 public keys out-of-the-box.
For cryptographic verification, feed it the output of the canonical
verifier's `--json` flag — that tool has already done the
Ed25519+VOPRF work.

## Roadmap

Scaffold → v0.2:

- [x] File drop + paste
- [x] Chain integrity check
- [x] Per-receipt table
- [ ] Compliance-export visualization (framework tabs with control coverage)
- [ ] Timeline view (events per hour / day)
- [ ] Export to PDF (auditor-ready)

Scaffold → v0.3:

- [ ] WebCrypto Ed25519 signature verification (trust anchors supplied)
- [ ] VOPRF token visual inspection
- [ ] Selective-disclosure commitment opener UI

## Deployment

This is a static site. Deploy anywhere:

```bash
# Cloudflare Pages
wrangler pages deploy packages/verify-cli/ecosystem/dashboard

# GitHub Pages
git subtree push --prefix=packages/verify-cli/ecosystem/dashboard origin gh-pages

# Local filesystem
open packages/verify-cli/ecosystem/dashboard/index.html
```

## License

Apache-2.0.
