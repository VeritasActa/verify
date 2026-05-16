# Veritas Acta Implementations Registry — Cloudflare Worker

Public, read-only registry of Veritas Acta ecosystem implementations.
Mirrors JSON files from `VeritasActa/agt-integration-profile/implementations/`
with cached responses and CORS enabled.

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/implementations.json` | List all registered implementations |
| GET | `/implementations/{name}.json` | Single implementation's record |
| GET | `/implementations/{name}/attestation.json` | Signed conformance attestation |
| GET | `/stats.json` | Aggregate stats (count, tier distribution) |
| GET | `/health` | Health probe |

## Implementation record format

```json
{
  "name": "sb-runtime",
  "repo": "https://github.com/ScopeBlind/sb-runtime",
  "version": "0.1.0",
  "claimed_tier": 4,
  "language": "Rust",
  "license": "Apache-2.0",
  "maintainer": "@tomjwxf",
  "conformance_evidence": "https://github.com/ScopeBlind/agent-governance-testvectors/actions/runs/12345678",
  "signed_attestation_hash": "sha256:abc123...",
  "registered_at": "2026-04-19T00:00:00.000Z"
}
```

## Deployment

```bash
wrangler deploy
```

Bind a KV namespace named `REGISTRY_CACHE` for caching. Zero-config
deployments work but miss the cache; responses will hit GitHub's API
directly (rate-limited to 60 req/hour unauthenticated).

## Register an implementation

Open a PR against `VeritasActa/agt-integration-profile` adding:

1. `implementations/{name}.json` — record metadata
2. `implementations/{name}/attestation.json` — signed conformance attestation

The registry serves updates automatically after PR merge.

## License

Apache-2.0
