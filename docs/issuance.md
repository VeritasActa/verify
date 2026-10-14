# Issuance and adapters

These are **optional producer tools**, not prerequisites for checking a receipt.
For recipient verification, [start here](../README.md#verify-an-existing-receipt).

## Before issuing

Decide which actions are instrumented, what policy/context is disclosed, who controls
the signing key, how recipients obtain it independently, and how you rotate/revoke it.
Signing an assertion does not make it true or demonstrate that unobserved actions
could not occur.

## Available tools

```bash
# Inspect and configure supported integrations (review configuration before applying)
verify init

# Wrap an MCP server; configure policy and signing according to your deployment
verify proxy --target "your-server-command"

# Local signing service for supported clients
verify daemon
```

These commands can create keys, write configuration or run services. They are not
part of the browser verifier and do not inherit its no-network execution boundary.
See the [advanced command reference](reference.md#subcommands), command `--help`,
and [threat model](../THREAT-MODEL.md) before operating them with real workloads.

Export a current receipt, independently distribute the expected public key, and
exercise successful verification, a wrong key, payload mutation and missing key.
Do not introduce an embedded-key fallback merely to make an example pass.
