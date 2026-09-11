import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Ordered by the public commitment contract. Reordering changes the source
// commitment, so the generator and runtime must share this exact list.
export const SIGIL_MONITORED_FILES = Object.freeze([
  'README.md',
  'cli.js',
  'src/sigil-policy.js',
  'src/detect.js',
  'src/conformance.js',
  'src/errors.js',
  'src/engines/ed25519-receipt.js',
  'src/engines/gate-receipt.js',
  'src/engines/claims-v211.js',
  'src/generated/claims-v211-schemas.js',
  'src/engines/macro-snapshot.js',
  'src/engines/legate-governed-receipt.js',
  'src/engines/legate-proof-pack.js',
  'src/engines/legate-standard.js',
  'src/engines/trusted-context-pack.js',
  'src/engines/commitment-mode.js',
  'src/engines/voprf-token.js',
  'src/engines/knowledge-unit.js',
  'src/engines/selective-disclosure.js',
  'src/engines/sigil.js',
  'src/engines/attestation.js',
  'src/engines/bulk.js',
  'src/engines/diff.js',
  'src/engines/init.js',
  'src/engines/proxy.js',
  'src/engines/daemon.js',
  'src/engines/prompt.js',
  'src/engines/chain-explore.js',
  'src/engines/compliance-export.js',
  'src/engines/dsse.js',
  'src/engines/delegation.js',
  'src/engines/cosign.js',
  'src/engines/dashboard.js',
  'src/engines/rekor.js',
  'src/engines/attestation-quote.js',
  'src/engines/watch.js',
  'src/engines/sbom.js',
  'src/engines/transparency.js',
  'src/engines/policy-decision-reexec.js',
  'src/context/live-context.js',
  'src/output/eat.js',
  'src/output/terminal.js',
  'src/output/json.js',
  'src/output/html-report.js',
  'src/util/canonical.js',
  'src/util/hex.js',
  'src/util/jwks.js',
  'src/util/audit-log.js',
  'src/util/fips.js',
  'src/util/known-issuers.js',
  'src/util/brass-v2.js',
  'src/util/merkle.js',
  'src/util/voprf-crypto.js',
  'src/util/voprf-crypto-v2.js',
]);

/**
 * Read the complete declared Sigil surface in commitment order.
 * Missing or unreadable inputs are semantic failures, never a smaller surface.
 */
export function readSigilMonitoredSource(root, files = SIGIL_MONITORED_FILES) {
  const buffers = [];
  const failures = [];
  for (const relativePath of files) {
    try {
      buffers.push(readFileSync(join(root, relativePath)));
    } catch (error) {
      failures.push({
        path: relativePath,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  if (failures.length) {
    const detail = failures.map(({ path }) => path).join(', ');
    const error = new Error(`Sigil monitored surface is incomplete: ${detail}`);
    error.code = 'SIGIL_MONITORED_SURFACE_INCOMPLETE';
    error.failures = failures;
    throw error;
  }
  return Buffer.concat(buffers);
}
