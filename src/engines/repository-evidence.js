/** Offline repository evidence. The shared core verifies all signed bindings;
 * the receiver's GitHub API readback remains explicitly an attestation. */
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
import { verifyRepositoryEvidence } from './legate-core.mjs';
export async function verifyRepositoryArtifact(input, opts = {}) {
  const result = await verifyRepositoryEvidence(input, opts.publicKey);
  const state = input?.state?.payload;
  return {
    ...result,
    format: 'repository-evidence',
    artifact_type: 'scopeblind.repository.evidence.v1',
    artifact_id: state?.task?.payload?.id,
    title: result.valid ? 'Repository evidence verifies' : 'Repository evidence does not verify',
    error: result.valid ? undefined : 'invalid_repository_evidence',
    publicKey: state?.task?.payload?.authority_key,
    keySource: result.authorityPinned ? 'independently pinned via --key' : 'included, not independently pinned',
    status: result.valid ? state.status : undefined,
    checks: [{ id: 'signed_records', label: 'Signatures and exact bindings', ok: result.valid, detail: result.valid ? 'Task, participants, reviewed snapshot and any later decisions bind to one another.' : result.errors.join('; ') }],
    establishes: result.valid ? ['The included keys signed these exact recorded statements.', ...(state.outcome ? [`The receiver recorded ${state.outcome.payload.status} with ${state.outcome.payload.readback} readback.`] : ['No repository outcome is recorded.']), ...(result.accepted ? ['The enrolled reviewer signed acceptance of this exact confirmed outcome.'] : ['Recipient acceptance is not established.'])] : [],
    not_established: result.limitations,
  };
}
