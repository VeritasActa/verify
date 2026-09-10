// Generates a real, signed RestraintReceipt sample: proof that an out-of-mandate
// order was blocked by the gate before it could reach the book. The receipt is a
// standard Legate governed receipt, so the open verify-cli re-verifies the exact
// signed bytes with zero ScopeBlind code.
//
// Usage: node samples/generate-restraint-sample.mjs [out.json]
// (run from packages/verify-cli; imports the built scopeblind-pm package)

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'

const PM = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..', 'scopeblind-pm')
const { evaluateGate } = await import(join(PM, 'dist', 'gateway.js'))
const { buildRestraintReceipt, openRestraint } = await import(join(PM, 'dist', 'restraint.js'))
const { deepSortKeys, clearSigningKeyCache } = await import(join(PM, 'dist', 'signing.js'))

const hex = (u) => Buffer.from(u).toString('hex')

// A vault with a fresh signing key + the desk mandate.
const v = mkdtempSync(join(tmpdir(), 'restraint-sample-'))
mkdirSync(join(v, 'policies'), { recursive: true })
writeFileSync(join(v, 'policies', 'mandate.cedar'), readFileSync(join(PM, 'policies', 'mandate.cedar'), 'utf-8'))
mkdirSync(join(v, 'receipts'), { recursive: true })
mkdirSync(join(v, '.scopeblind', 'keys'), { recursive: true })
const priv = ed25519.utils.randomSecretKey()
writeFileSync(
  join(v, '.scopeblind', 'keys', 'signing.json'),
  JSON.stringify({ kid: 'sb:desk:eq-1', public_key: hex(ed25519.getPublicKey(priv)), private_key: hex(priv) }),
)
clearSigningKeyCache()

// The agent's signed authority manifest forbids this instrument outright.
const mkey = ed25519.utils.randomSecretKey()
const manifestCore = {
  type: 'scopeblind.agent_authority.v1',
  agent_id: 'agent:eq-desk',
  parent_mandate_digest: null,
  authority: { forbidden_instruments: ['TSLA'] },
  expires_at: null,
  verification_key: hex(ed25519.getPublicKey(mkey)),
}
const manifest = {
  ...manifestCore,
  signature: hex(ed25519.sign(sha256(new TextEncoder().encode(JSON.stringify(deepSortKeys(manifestCore)))), mkey)),
}

// The portfolio the gate sizes against.
const portfolio = {
  equity: 1_000_000,
  cash: 300_000,
  positions: [{ symbol: 'AAPL', qty: 100, current_price: 200, sector: 'tech' }],
  sector_weights: { tech: 0.02 },
}

// The agent proposes a large single-name order in the forbidden instrument.
const order = { symbol: 'TSLA', side: 'buy', qty: 5000, price: 400, asset_class: 'equity' }

const gate = await evaluateGate(v, order, portfolio, { record: false, manifest })
if (gate.decision !== 'deny') {
  console.error('expected a deny; the mandate did not block the order')
  process.exit(1)
}

// Mint the signed restraint receipt. Fixed salt + timestamp keep the sample
// stable across regenerations.
const receipt = buildRestraintReceipt(v, gate, order, {
  salt: 'sample-restraint-salt-000000000000',
  at: '2026-06-21T12:00:00.000Z',
})

const out = process.argv[2] || join(fileURLToPath(new URL('.', import.meta.url)), 'sample-restraint-receipt.json')
writeFileSync(out, JSON.stringify(receipt, null, 2) + '\n')

const opened = openRestraint(receipt)
console.error(`wrote ${out}`)
console.error(`  decision: ${receipt.decision}  tool: ${receipt.tool}`)
console.error(`  determining: ${receipt.restraint.outcome.determining.join(', ')}`)
console.error(`  risk_band: ${receipt.restraint.outcome.risk_band}`)
console.error(`  bindings: outcome_bound=${opened.outcome_bound} proposed_bound=${opened.proposed_bound}`)
