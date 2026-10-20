# TRACE Acta fixtures

This package's `cli.js` against the Acta action-receipt fixtures that [agentrust-io/trace-spec](https://github.com/agentrust-io/trace-spec) publishes, run by [`scripts/trace-fixtures.mjs`](../scripts/trace-fixtures.mjs) and checked on every push by [`.github/workflows/trace-fixtures.yml`](../.github/workflows/trace-fixtures.yml), which fails when this page differs from a new run. TRACE's Project Lead asked, on agentrust-io/trace-spec#469, that each implementation run such checks from its own repository and publish the results there.

- Repository: [agentrust-io/trace-spec](https://github.com/agentrust-io/trace-spec)
- Commit: [`b8d2ce6161e57d41dd0b49be78efc05e86baeca5`](https://github.com/agentrust-io/trace-spec/tree/b8d2ce6161e57d41dd0b49be78efc05e86baeca5)
- Fixtures: `examples/action-receipts/acta`, the 11 that `expected.json` lists
- Run: `node cli.js <fixture> --jwks acta-keys.json --json`, adding `--previous <predecessor>` for each fixture `expected.json` gives a predecessor in `chain`
- Result: 11 fixtures, 35 checks compared, no differences

## How each column is decided

The CLI's `--json` result gives each check it made in `checks`, with a result of `pass`, `fail` or `undecidable`. A check that an earlier refusal left unreached (`not_run`) is shown as not reached and not compared: the CLI refuses a receipt whose signing input carries a signature member before checking its signature. Any other result decides nothing, and differs from `pass` or `fail`.

| `expected.json` column | CLI check | Fails with | What is checked |
| --- | --- | --- | --- |
| `signing_input` | `checks.signing_input` | `signature_in_signing_input` | The signing input carries no `signature` member (draft §6.6). |
| `signature` | `checks.signature` | `invalid_signature` | Ed25519 over the JCS signing input, under the key acta-keys.json gives the receipt's `kid`. |
| `key_window` | `checks.key_window` | `key_outside_validity_window` | The receipt's `issued_at` is inside that key's `valid_from` / `valid_until` window (§5.5 of the -04 editor's copy, VeritasActa/drafts; §9.2 of -03). |
| `chain` | `checks.previous` | `chain_break`, `malformed_chain_link`, `unsupported_chain_hash_algorithm` | Run with `--previous <predecessor>`: the receipt's `previousReceiptHash` is the §6.7 link of the predecessor expected.json names (§6.7.1 of the -04 editor's copy, VeritasActa/drafts). |

For each fixture the verdict is invalid when `expected.json` fails any of these columns, and valid otherwise. The CLI's `outcome` and exit status must be that verdict, and its `error` must be a code that fails one of the columns `expected.json` fails.

## Not compared

| `expected.json` column | Why |
| --- | --- |
| `policy_freshness` | It compares `policy_digest` with expected.json's `current_policy_digest`. The CLI takes no policy context, so it does not decide whether a policy is still in force. |
| `session_binding` | It compares `session_id` with expected.json's `expected_session_id`. The CLI takes no session context, so it does not decide which session a receipt belongs to. |

So fixtures `05` and `06`, which fail only these columns, are valid here, as they should be for a verifier given no policy or session context.

## Results

| Fixture | `--previous` | Exit | Outcome | Code | `signing_input` | `signature` | `key_window` | `chain` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `01-valid-accepted.json` |  | 0 | valid |  | pass | pass | pass | n/a |
| `02-valid-denied.json` | `01-valid-accepted.json` | 0 | valid |  | pass | pass | pass | pass |
| `03-signature-key-mismatch.json` |  | 1 | invalid | `invalid_signature` | pass | fail | pass (not compared) | n/a |
| `04-broken-chain.json` | `02-valid-denied.json` | 1 | invalid | `chain_break` | pass | pass | pass | fail |
| `05-stale-policy-digest.json` |  | 0 | valid |  | pass | pass | pass | n/a |
| `06-session-binding-mismatch.json` |  | 0 | valid |  | pass | pass | pass | n/a |
| `07-valid-inside-key-window.json` |  | 0 | valid |  | pass | pass | pass | n/a |
| `08-valid-prefixed-chain-link.json` | `07-valid-inside-key-window.json` | 0 | valid |  | pass | pass | pass | pass |
| `09-payload-only-chain-link.json` | `07-valid-inside-key-window.json` | 1 | invalid | `chain_break` | pass | pass | pass | fail |
| `10-signature-member-in-payload.json` |  | 1 | invalid | `signature_in_signing_input` | fail | not reached | pass | n/a |
| `11-outside-key-window.json` |  | 1 | invalid | `key_outside_validity_window` | pass | pass | fail | n/a |
