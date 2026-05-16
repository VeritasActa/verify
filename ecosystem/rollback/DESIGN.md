# Filesystem Rollback — AIP-0004 (v0.6.0 target)

> **Spec:** [AIP-0004 Content-Addressed Snapshot and Rollback Receipts](../../../../specs/aip/AIP-0004-snapshot-receipts.md)
> **Reference implementation:** [`snapshot.mjs`](./snapshot.mjs) (Merkle helper + payload builder)
> **Schema:** [`snapshot-receipt.schema.json`](./snapshot-receipt.schema.json)
> **Tests:** 11 units in `test/unit/snapshot.test.js` (determinism, path-order independence, tamper detection, odd-layer duplication, payload validation)



Content-addressed filesystem snapshots before each receipted session,
with one-command rollback on anomaly detection. Matches nono's undo
pattern but pairs it with Veritas Acta receipts so rollback events are
themselves signed.

## Goal

When an agent session goes wrong, roll back to the pre-session state
without losing the receipt trail. The receipts survive; the filesystem
reverts.

## Design

### Snapshot primitive

- Before every session, hash the files the session will touch (derived
  from the agent's allowlist / policy)
- Store content-addressed copies in `.veritasacta/snapshots/{session_id}/`
- Content-addressed dedup: files common across sessions are stored once
- Snapshot index committed to receipts via `snapshot_digest` field

### Rollback command

```bash
veritasacta rollback --session <session_id>
```

Restores files to their pre-session state. Emits a signed `rollback`
receipt linked to the original session.

### Composition with sb-runtime

sb-runtime already has filesystem isolation via Landlock. The rollback
layer adds temporal reversion: not "the agent can't write here" but
"if the agent wrote here, we can undo it."

## Non-goals

- Not a general-purpose file versioning system (use git)
- Not a replacement for kernel sandboxing (compose with sb-runtime)
- Not guaranteed to roll back external side-effects (API calls, db
  mutations). Those require receipts to be inspected and externally
  compensated.

## Implementation path

- v0.6.0: manual snapshot/rollback commands + session_id linkage
- v0.7.0: automatic anomaly-triggered rollback (ties to supervisor
  approval workflow)

## License

Apache-2.0 once shipped.
