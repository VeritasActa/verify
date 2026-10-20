/**
 * The run-manifest check with --receipts reads the receipt chain with the website's verifier, bundled into
 * src/engines/legate-core.mjs from packages/scopeblind-pm/web/src/acta-receipt.ts. From 0.10.26 it reads each link
 * as the receipt verifier does (checkChainLinkSyntax), lowercase hex only, and refuses a link over the previous
 * receipt's payload alone whatever that receipt cites, as --replay-chain does from 0.10.25.
 *
 * The fixture's receipts are relinked here without being signed again. Relinked under section 6.7 they are the
 * fixture's own receipts, so every signature holds; relinked any other way their signatures no longer hold, and
 * chain_unbroken reports the links alone.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyLegateStandard } from '../../src/engines/legate-standard.js';
import { checkChainLinkSyntax } from '../../src/engines/ed25519-receipt.js';
import { canonicalize } from '../../src/util/canonical.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => JSON.parse(readFileSync(join(here, '..', 'fixtures', 'legate', name), 'utf8'));
const NOW = new Date('2026-09-12T00:00:00Z');
const sha = (value) => createHash('sha256').update(canonicalize(value), 'utf8').digest('hex');

/** The fixture's receipts in order, each linked to the one before by link(previous); spec dropped when asked. */
function relink(link, { dropSpec = false } = {}) {
  const out = [];
  for (const receipt of fixture('run-receipts.json')) {
    const payload = { ...receipt.payload };
    delete payload.previousReceiptHash;
    if (dropSpec) delete payload.spec;
    if (out.length) payload.previousReceiptHash = link(out[out.length - 1]);
    out.push({ ...receipt, payload });
  }
  return out;
}

async function chainOf(receipts) {
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, receipts });
  assert.ok(r.chain, 'the run-manifest check reads the receipts');
  return r.chain;
}

test('relinked under section 6.7, the receipts are the fixture\'s own: signed and unbroken', async () => {
  const chain = await chainOf(relink((previous) => `sha256:${sha(previous)}`));
  assert.equal(chain.chain_unbroken, true);
  assert.equal(chain.all_signatures_valid, true);
});

test('the bundled core refuses a payload-only link, after a receipt citing -03 or citing nothing', async () => {
  // 0.10.25's core read the second case as linked ("pre-03 rule"), since the receipt before cited no spec.
  for (const dropSpec of [false, true]) {
    const chain = await chainOf(relink((previous) => `sha256:${sha(previous.payload)}`, { dropSpec }));
    assert.equal(chain.chain_unbroken, false, `spec dropped: ${dropSpec}`);
  }
});

test('the bundled core accepts exactly the link forms checkChainLinkSyntax accepts', async () => {
  const forms = {
    'sha256: and lowercase hex': (previous) => `sha256:${sha(previous)}`,
    'bare lowercase hex': (previous) => sha(previous),
    'sha256: and uppercase hex': (previous) => `sha256:${sha(previous).toUpperCase()}`,
    'bare uppercase hex': (previous) => sha(previous).toUpperCase(),
    'an uppercase prefix': (previous) => `SHA256:${sha(previous)}`,
    'a space after the prefix': (previous) => `sha256: ${sha(previous)}`,
    'another hash algorithm': () => `sha512:${'ab'.repeat(64)}`,
  };
  for (const [name, form] of Object.entries(forms)) {
    const receipts = relink(form);
    const syntax = receipts.slice(1).map((receipt) => checkChainLinkSyntax(receipt.payload).error);
    const chain = await chainOf(receipts);
    assert.equal(chain.chain_unbroken, syntax.every((error) => !error), name);
    // A link naming another algorithm leaves the chain undecided rather than broken (§5.3 of the -04 editor's copy,
    // VeritasActa/drafts), as on a receipt.
    const expected = syntax.every((error) => !error) ? 'unbroken' : syntax.every((error) => error === 'unsupported_chain_hash_algorithm') ? 'undecidable' : 'broken';
    assert.equal(chain.chain_outcome, expected, name);
  }
});
