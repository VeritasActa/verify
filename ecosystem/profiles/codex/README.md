# Profile: OpenAI Codex CLI

Stricter default than `claude-code` because Codex CLI's tool behavior is more aggressive and the profile assumes a CI / unattended deployment context.

## Key differences from claude-code

- **Exec default-deny**: only `ls`, `cat`, `grep`, `rg`, `find`, `head`, `tail`, `wc` are allowed. Add your build / test commands explicitly per project.
- **Network narrower**: only `*.openai.com`, `api.github.com`, `githubusercontent.com`, `pypi.org`, `npmjs.org`.
- **`chmod` / `chown` denied**: Codex has a pattern of suggesting permission changes; blocking at the policy layer forces explicit operator action.

## Extending for your project

Copy `policy.cedar` and add a project-specific allowlist:

```cedar
// Your project-specific build commands
permit (
    principal is Agent::Principal,
    action == Agent::Action::"exec",
    resource
) when {
    context.command in ["npm", "pytest", "cargo"]  // whatever your stack needs
};
```

Keep the original deny rules; they're defense in depth.

## Composition

Standalone (sb-runtime Ring 3):

```bash
sb-runtime --ring 3 --profile ./profile.yaml -- codex
```

With nono (recommended for production):

```bash
nono run --caps ./nono-capabilities.yaml -- \
    sb-runtime --ring 2 --policy ./policy.cedar -- codex
```
