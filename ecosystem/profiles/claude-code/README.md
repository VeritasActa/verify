# Profile: Claude Code

Run [Anthropic Claude Code](https://www.claude.com/product/claude-code) under sb-runtime + nono + signed receipts with one command.

## Quick start

```bash
# Option A: via verify init
cd my-project
npx @veritasacta/verify init --profile claude-code

# Option B: via sb-runtime directly
sb-runtime run --profile ./profile.yaml --ring 3 -- claude

# Option C: nono + sb-runtime composition (Linux, recommended for production)
nono run --caps ./nono-capabilities.yaml -- \
    sb-runtime --ring 2 --policy ./policy.cedar -- claude
```

## What the profile allows

- **Reads** from `/workspace/*` and `/tmp/*`
- **Writes** inside `/workspace/*` only
- **Exec** of a safe allowlist: `ls`, `cat`, `grep`, `rg`, `git`, `pytest`, `npm`, `node`, `cargo`, `go`, and similar dev tools
- **HTTPS fetches** to `api.github.com`, `githubusercontent.com`, `anthropic.com`, `pypi.org`, `registry.npmjs.org`

## What the profile denies

- Cloud metadata endpoints (AWS IMDS, GCP metadata, IPv6 equivalents)
- Writes to `/etc`, `/usr`, `/root`, `/var/log`, `/sys`, `/proc`
- Reads of credential patterns (`*.pem`, SSH keys, AWS creds, `.netrc`, `secrets.*`)
- Destructive shell commands (`rm`, `dd`, `mkfs`, `shutdown`, force-push to git)

## Receipt format

Every tool call emits a receipt at `.veritasacta/receipts/claude-code/<sequence>.json` in the Veritas Acta format (draft-farley-acta-signed-receipts-02). Verify offline:

```bash
npx @veritasacta/verify .veritasacta/receipts/claude-code/ --key operator-public.pem
```

## When to customise

- **Cursor, Codex, or another IDE-embedded agent** — copy this profile and relax the HTTPS allowlist (Cursor talks to its own backend)
- **Production CI** — tighten to deny-by-default on exec, add an explicit allowlist only for your build commands
- **Enterprise with air-gap** — remove the network block entirely, keep only Cedar allow/deny on file and exec

## Threat model

This profile assumes Claude Code is **semi-trusted**: we trust the binary is unmodified (verified via Anthropic's signing) but don't trust any prompt or tool-use output to be safe. The sandbox is the enforcement boundary; Cedar policy is the audit boundary.

Known attack vectors this profile addresses:

- **Credential exfiltration via file read** — blocked at policy + nono filesystem layer
- **Cloud metadata access (SSRF-like)** — blocked at network layer
- **Destructive shell via LLM confusion** — blocked at Cedar exec allowlist
- **System-file tampering** — blocked at policy + nono filesystem layer

Known attack vectors **NOT** addressed (need operator-specific handling):

- **Data exfiltration via allowed HTTPS endpoints** — Claude Code can post to api.github.com; if that's a real concern, narrow the allowlist further
- **Supply-chain attacks via allowed package managers** — `npm install` of a malicious package is not blocked; use [`verify prompt <file>`](../../../src/engines/prompt.js) to verify `.claude/settings.json` and `CLAUDE.md` provenance

## Maintaining this profile

Profile updates follow semver. The current version is 1.0.0. Changes:

- **Patch** — allowlist additions for already-covered command families
- **Minor** — new action types (e.g., a new Claude Code tool), new endpoint allowlist entries
- **Major** — changes to default-deny posture or removal of previously-allowed patterns

File issues or proposed updates in the main [`VeritasActa/verify`](https://github.com/VeritasActa/verify) repo.
