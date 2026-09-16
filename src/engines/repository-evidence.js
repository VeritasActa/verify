/** Offline repository evidence. The shared core verifies all signed bindings;
 * the receiver's GitHub API readback remains explicitly an attestation. */
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
import { verifyRepositoryEvidence, verifyRepositoryCollaborationEvidence, verifyRepositoryReviewEvidence } from './legate-core.mjs';
export async function verifyRepositoryArtifact(input, opts = {}) {
  const review = input?.type === 'scopeblind.repository.review-evidence.v1';
  const nested = review ? input.repository : input;
  const collaboration = nested?.type === 'scopeblind.repository.collaboration-evidence.v1';
  const result = await (review ? verifyRepositoryReviewEvidence : collaboration ? verifyRepositoryCollaborationEvidence : verifyRepositoryEvidence)(input, opts.publicKey);
  const state = (collaboration ? nested?.repository : nested)?.state?.payload;
  return {
    ...result,
    format: 'repository-evidence',
    artifact_type: review ? 'scopeblind.repository.review-evidence.v1' : collaboration ? 'scopeblind.repository.collaboration-evidence.v1' : 'scopeblind.repository.evidence.v1',
    artifact_id: state?.task?.payload?.id,
    title: result.valid ? 'Repository evidence verifies' : 'Repository evidence does not verify',
    error: result.valid ? undefined : 'invalid_repository_evidence',
    publicKey: state?.task?.payload?.authority_key,
    keySource: result.authorityPinned ? 'independently pinned via --key' : 'included, not independently pinned',
    status: result.valid ? state.status : undefined,
    checks: [{ id: 'signed_records', label: 'Signatures and exact bindings', ok: result.valid, detail: result.valid ? 'Task, participants, reviewed snapshot and any later decisions bind to one another.' : result.errors.join('; ') }],
    establishes: result.valid ? ['The included keys signed these exact recorded statements.', ...(result.originVerified ? ['The new task was adopted from a scoped draft naming the exact preserved source feedback; prior approvals were not copied.'] : []), ...(result.packetVerified ? ['The owner-signed brief, acceptance criteria and receiver preview observation bind to the exact proposal.'] : []), ...(result.decisionsVerified ? ['Both participants signed that exact packet beside their exact merge approvals.'] : []), ...(result.previewVerified ? ['The fixed contact-page preview matches the receiver-signed proposal and canonical file hashes.'] : []), ...(result.revisionLinked ? ['The revision names the included predecessor and its exact feedback.'] : []), ...(state.outcome ? [`The receiver recorded ${state.outcome.payload.status} with ${state.outcome.payload.readback} readback.`] : ['No repository outcome is recorded.']), ...(result.accepted ? ['The enrolled reviewer signed acceptance of this exact confirmed outcome.'] : ['Recipient acceptance is not established.'])] : [],
    not_established: result.limitations,
  };
}
