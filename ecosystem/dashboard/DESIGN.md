# Audit Dashboard GUI (v0.6.0 target)

Web-based dashboard for receipt chain visualization, audit report
generation, and conformance monitoring. Standalone web app at
`dashboard.scopeblind.com` (managed, commercial tier) and open-source
self-host version.

## Scope

### Views

1. **Chain view** — timeline of receipts in a session with
   chain-integrity visualization (Signet-style)
2. **Per-receipt detail** — full receipt payload, verification result,
   tier, attestation links
3. **Conformance report** — tier distribution, top issuers, error
   distribution
4. **Audit report generator** — one-click export of an HTML / PDF
   report for auditor delivery
5. **Anomaly detection** — flag unusual patterns (sudden tier drops,
   chain breaks, unsigned deltas)

### Inputs

- Upload a JSONL receipt chain
- Connect to an S3 / GCS / Azure bucket with receipts
- Subscribe to a live Rekor transparency log feed (v0.7+)

### Outputs

- HTML audit report (matches `--audit-report` CLI output)
- PDF auditor deliverable
- Signed canonical attestation of the dashboard session

## Technology

- Frontend: React + Tailwind (matches Sigil site aesthetic)
- Backend: self-hostable Go / Node server, or Cloudflare Worker for
  the managed tier
- Auth: optional; anonymous by default for the self-host version

## Commercial tier (dashboard.scopeblind.com)

- Hosted version with SSO, multi-tenant, retention tiers
- Free tier: 1 user, 30-day retention, 10K receipts/month
- Team: $199/mo (10 users, 1-year retention, 1M receipts/month)
- Enterprise: custom

## License

Apache-2.0 once shipped (for self-host); hosted service is proprietary.
