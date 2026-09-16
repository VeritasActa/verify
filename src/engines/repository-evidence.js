/** Offline repository evidence. The shared core verifies all signed bindings;
 * the receiver's GitHub API readback remains explicitly an attestation. */
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
import { verifyRepositoryEvidence, verifyRepositoryCollaborationEvidence, verifyRepositoryReviewEvidence, verifyRepositoryCodingEvidence } from './legate-core.mjs';
export async function verifyRepositoryArtifact(input, opts = {}) {
  if (input?.type === 'scopeblind.repository.coding-evidence.v1') {
    const result=await verifyRepositoryCodingEvidence(input,opts.publicKey),job=result.valid?input.job.payload:null;
    return {...result,accepted:false,format:'repository-evidence',artifact_type:input.type,artifact_id:job?.request.payload.id,
      title:result.valid?'Code-work evidence verifies':'Code-work evidence does not verify',error:result.valid?undefined:'invalid_repository_coding_evidence',
      publicKey:job?.workspace.payload.workspace.payload.authority_key,keySource:result.authorityPinned?'independently pinned via --key':'included, not independently pinned',status:job?.status,
      checks:[{id:'coding_records',label:'Separate coding authority, exact source and publication bindings',ok:result.valid,detail:result.valid?'Both members signed the bounded mandate; the exact feedback and recorded worker result are linked.':result.errors.join('; ')}],
      establishes:result.valid?['Both project members signed this bounded code-edit mandate.','The request identifies the exact source review and recorded feedback.',...(result.published?['The worker attests to a new pull request and preview at the exact planned commit; the service admitted that publication.']:['Publication is not established.']),'A merge and recipient acceptance require separate human decisions.']:[],not_established:result.limitations};
  }
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
    establishes: result.valid ? ['The included keys signed these exact recorded statements.', ...(result.codingOriginVerified ? ['The fresh review adopts the exact result of a separately authorized coding job and preserves its source feedback; earlier approvals were not copied.'] : []), ...(result.originVerified ? ['The new task was adopted from a scoped draft naming the exact preserved source feedback; prior approvals were not copied.'] : []), ...(result.packetVerified ? ['The owner-signed brief, acceptance criteria and receiver preview observation bind to the exact proposal.'] : []), ...(result.decisionsVerified ? ['Both participants signed that exact packet beside their exact merge approvals.'] : []), ...(result.previewVerified ? ['The fixed contact-page preview matches the receiver-signed proposal and canonical file hashes.'] : []), ...(result.revisionLinked ? ['The revision names the included predecessor and its exact feedback.'] : []), ...(state.outcome ? [`The receiver recorded ${state.outcome.payload.status} with ${state.outcome.payload.readback} readback.`] : ['No repository outcome is recorded.']), ...(result.accepted ? ['The enrolled reviewer signed acceptance of this exact confirmed outcome.'] : ['Recipient acceptance is not established.'])] : [],
    not_established: result.limitations,
  };
}
