# Ecosystem examples and historical designs

This directory preserves optional integration code, configuration examples and
design proposals. It is **not a list of supported deployments or published
packages**. The old v0.5.0 deployment checklist and v0.6/v0.7 delivery promises are
superseded by this status page.

For the maintained verifier, start with the [repository README](../README.md),
[contribution guide](../CONTRIBUTING.md) and [release history](../CHANGELOG.md).
Optional CLI producer commands have a separate [issuance guide](../docs/issuance.md).

## What is here

| Material | Paths | Status and use |
| --- | --- | --- |
| Framework adapters and signing helpers | `adapters/`, `sdk-js/`, `sdk-py/` | Reference implementations and proposals. Framework compatibility, package publication and current receipt conformance must be checked individually. |
| Assistant integrations and policies | `claude-code-plugin/`, `wshobson-plugin/`, `profiles/` | Historical configuration examples. Review permissions, commands and current host support before use; these are not an isolation guarantee. |
| Distribution helpers | `github-action/`, `homebrew-tap/` | Experimental integration code, not a release-qualified installation path. Use the documented npm/CLI path for the current verifier. |
| Service prototypes | `registry-worker/`, `badge-worker/`, `dashboard/`, `interop-leaderboard/`, `certify/` | Prototype source and workflow templates. Their presence does not establish a live service or independent certification. |
| Filesystem snapshots | `rollback/` | Prototype with local unit tests in `test/unit/snapshot.test.js`; not a transactional rollback guarantee for external systems. |
| Designs | `browser-extension/`, `cosign-compat/`, `ebpf-observer/`, `physical-attestation/`, `reputation/`, `supervisor/`, `vscode-extension/` | Research/design material. A design document does not establish a shipped feature or security property. |

The core CI workflow does not install and exercise every external framework, host
or service listed here. Old package versions, commands and monorepo paths in nested
documents are historical context, not current setup instructions.

In particular, the experimental GitHub Action constructs shell commands from its
inputs, including an `eval` of the receipt path. Do not pass untrusted values to it
or treat it as the recommended CI integration. Use a fixed, reviewed CLI command
with an explicit key and pinned package version instead.

## Promoting an integration to maintained status

Start with an issue identifying the actual consuming project and a willing
maintainer. A focused contribution should provide:

1. A clean installation against pinned, current dependencies, without private
   monorepo paths or undeclared services.
2. A generated receipt that the current verifier checks under an independently
   supplied test key, plus malformed, wrong-key and tampered negative cases.
3. CI for those commands and a precise statement of what the integration does and
   does not enforce.
4. A documented release/distribution path and a way to report bugs.

Until those exist, retain the reference status. For actual interoperability
evidence see [TRACE fixture results](../docs/trace-fixtures.md) and the
[shared conformance project](https://github.com/ScopeBlind/agent-governance-testvectors).
