/**
 * Terminal output formatter.
 *
 * Renders verification results with ANSI colors, Sigil art, and
 * conformance tier labels. Subtle ecosystem wayfinding (Protocol /
 * Managed URL lines) is included — factual, not promotional.
 *
 * @module verify-cli/src/output/terminal
 * @license Apache-2.0
 */

import { deriveFilteredSigil } from '../engines/sigil.js';

const isCI = Boolean(process.env.CI || process.env.NO_COLOR);

// ANSI color helpers (no-op in CI for log cleanliness)
const c = (code, s) => (isCI ? s : `\x1b[${code}m${s}\x1b[0m`);
export const green = (s) => c('32', s);
export const red = (s) => c('31', s);
export const yellow = (s) => c('33', s);
export const dim = (s) => c('2', s);
export const bold = (s) => c('1', s);
export const teal = (s) => c('36', s);
export const peach = (s) => (isCI ? s : `\x1b[38;5;216m${s}\x1b[0m`);

/**
 * The trust-tier line: states plainly what THIS verification relied on, so a
 * green verdict is never read as more than it is. Facts only, never a generic
 * "verified" badge; the closing clause states the standing deployment truth
 * (no independent witness countersignatures exist yet) rather than implying one.
 *
 * @param {{ keySource?: string, signerLabel?: string }} result
 * @returns {string}
 */
export function trustTierLine(result) {
  const src = String(result.keySource || '');
  let key;
  if (src === 'provided' || src.includes('pinned')) key = 'key pinned by the verifier';
  else if (src === 'jwks') key = "key resolved from the issuer's published JWKS (trust follows that endpoint)";
  else if (src === 'bundle') key = 'key carried in the evidence bundle (pin the bundle issuer to trust it)';
  else key = 'key embedded in the artifact (pin it against a source you trust before relying on it)';
  const label = result.signerLabel
    ? '; signer name from the known-issuers list (a display aid, not a trust anchor)'
    : '';
  return `  Trust tier: ${key}${label}.\n              ${dim('Signature checked offline. Log anchoring, if any, needs its own check; no independent witness countersignatures exist yet.')}`;
}

/**
 * Render the 11x11 terminal Sigil art for a public key.
 * Deterministic across runs for a given key.
 *
 * @param {string} publicKeyHex
 * @returns {string}
 */
export function renderTerminalSigil(publicKeyHex) {
  const { grid, fingerprint } = deriveFilteredSigil(publicKeyHex);
  const SIZE = 11;
  const cx = 5, cy = 5;
  const R = 5.5;
  const outerR = R;
  const midR = R * 0.72;
  const innerR = R * 0.44;
  const surroundR = innerR * 0.65;
  const diamondR = surroundR * 0.6;

  const lines = [];
  for (let y = 0; y < SIZE; y++) {
    let row = '  ';
    for (let x = 0; x < SIZE; x++) {
      const dx = x - cx;
      const dy = y - cy;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const angle = Math.atan2(dy, dx);
      const normAngle = angle < 0 ? angle + 2 * Math.PI : angle;
      const segIdx = Math.floor((normAngle / (2 * Math.PI)) * 6) % 6;

      let state = 0;
      if (dist <= diamondR) {
        if (angle >= -Math.PI && angle < -Math.PI / 2) state = grid.diamond.left;
        else if (angle >= -Math.PI / 2 && angle < 0) state = grid.diamond.top;
        else if (angle >= 0 && angle < Math.PI / 2) state = grid.diamond.right;
        else state = grid.diamond.bottom;
      } else if (dist <= surroundR) {
        const sIdx = Math.floor(((normAngle + Math.PI / 4) % (2 * Math.PI)) / (Math.PI / 2)) % 4;
        state = grid.surround[sIdx];
      } else if (dist <= innerR) state = grid.innerRing[segIdx];
      else if (dist <= midR) state = grid.midRing[segIdx];
      else if (dist <= outerR) state = grid.outerRing[segIdx];
      else {
        const cIdx = (y < cy ? 0 : 2) + (x < cx ? 0 : 1);
        const cornerAngle = Math.atan2(y - cy, x - cx);
        const cornerMidAngles = [-3 * Math.PI / 4, -Math.PI / 4, 3 * Math.PI / 4, Math.PI / 4];
        const half = (cIdx === 0 || cIdx === 1)
          ? (cornerAngle < cornerMidAngles[cIdx] ? 0 : 1)
          : (cornerAngle > cornerMidAngles[cIdx] ? 0 : 1);
        state = grid.corners[cIdx * 2 + half];
      }

      if (state === 1) row += teal('█');
      else if (state === 2) row += peach('▓');
      else row += dim('·');
    }
    lines.push(row);
  }
  lines.push(`  ${dim('sigil:')} ${teal(fingerprint)}`);
  return lines.join('\n');
}

const WAYFINDING = `  ${dim('Protocol:')} ${dim('https://veritasacta.com')}
  ${dim('Managed:')}  ${dim('https://scopeblind.com')} (optional)

  ${dim('No servers were contacted.')}`;

/**
 * Format a single-receipt verification result.
 *
 * @param {Object} result from any engine, normalized by cli.js
 * @param {Object} opts cli options
 * @returns {string}
 */
export function formatReceiptResult(result, opts = {}) {
  const lines = [];

  if (result.valid && result.publicKey && result.publicKey.length === 64 && !isCI && !opts.noSigil) {
    lines.push('');
    lines.push(renderTerminalSigil(result.publicKey));
  }

  const icon = result.valid ? green('✓') : red('✗');
  const status = result.valid ? green('VALID') : red('INVALID');
  lines.push(`\n${icon} Signature: ${status}`);

  if (result.format) lines.push(`  Format:     ${result.format}${result.specVersion ? ` (${result.specVersion})` : ''}`);
  if (result.modeLabel) lines.push(`  Mode:       ${result.modeLabel}`);
  if (result.type) lines.push(`  Type:       ${result.type}`);
  if (result.algorithm) lines.push(`  Algorithm:  ${result.algorithm}`);
  if (result.kid) lines.push(`  Kid:        ${result.kid}`);
  if (result.issuer) lines.push(`  Issuer:     ${result.issuer}`);
  if (result.keySource) lines.push(`  Key:        ${result.keySource}`);
  if (result.publicKey) lines.push(trustTierLine(result));
  if (result.tier) lines.push(`  Tier:       ${result.tier.label} ${dim(`(${result.tier.features.join(', ')})`)}`);
  if (result.nullifier) lines.push(`  Nullifier:  ${result.nullifier.slice(0, 16)}...`);
  if (result.scope) {
    if (typeof result.scope === 'string') {
      lines.push(`  Scope:      ${result.scope}`);
    } else if (typeof result.scope === 'object') {
      const s = result.scope;
      const parts = [];
      if (s.origin !== undefined) parts.push(`origin=${s.origin}`);
      if (s.epoch !== undefined) parts.push(`epoch=${s.epoch}`);
      if (s.sub !== undefined) parts.push(`sub=${s.sub}`);
      if (parts.length > 0) lines.push(`  Scope:      ${parts.join(', ')}`);
    }
  }
  if (result.transport_hint) lines.push(`  Transport:  ${result.transport_hint}`);

  if (result.attestationMode) {
    lines.push(`  Attestation: ${result.attestationMode}`);
    if (result.attestationMode.startsWith('hardware:')) {
      lines.push(`  ${dim('Hardware-rooted attestation; see https://scopeblind.com/seal for details.')}`);
    }
  }

  if (result.disclosedFields && result.disclosedFields.length > 0) {
    lines.push(`  Disclosed:  ${result.disclosedFields.join(', ')}`);
  }
  if (result.redactedFields && result.redactedFields.length > 0) {
    lines.push(`  Hidden:     ${result.redactedFields.length} field(s) (cryptographically committed)`);
  }

  if (result.contextChecks && result.contextChecks.length > 0) {
    lines.push(`  ${bold('Context checks:')}`);
    for (const check of result.contextChecks) {
      const ico = check.satisfied ? green('✓') : red('✗');
      lines.push(`    ${ico} ${check.kind}: ${check.detail}`);
    }
  }

  if (result.evidenceGrade) {
    const GRADE_PROVES = {
      'signed': 'integrity only; does not prove the action ran elsewhere',
      'policy-bound': 'bound to the committed policy verdict',
      'device-authorized': 'a paired-device signature authorized the action',
      'runtime-and-output-bound': 'execution profile + output hashes bound in',
      'externally-corroborated': 'an independent external system confirmed the outcome',
    };
    const proves = GRADE_PROVES[result.evidenceGrade] || '';
    lines.push(`  ${bold('Evidence:')}   ${result.evidenceGrade}${proves ? ` ${dim(`(${proves})`)}` : ''}`);
    for (const lim of (result.evidenceLimitations || [])) {
      lines.push(`    ${yellow('!')} ${dim(lim)}`);
    }
  }
  if (result.entitlementVerifiedByRuntime) {
    lines.push(`  ${bold('Entitlement:')} pinned issuer proof verified by the receipt runtime ${dim('(full blinded proof withheld from normal receipt sync)')}`);
  } else if (result.entitlementAttested) {
    lines.push(`  ${bold('Entitlement:')} legacy entitlement claim present ${dim('(this verifier did not independently verify the issuer proof)')}`);
  }

  if (result.hash) lines.push(`  Hash:       ${dim(result.hash)}`);

  if (result.error && !result.valid) {
    lines.push(`  Error:      ${red(result.error)}`);
    if (result.errorMeta?.spec) lines.push(`  Spec:       ${dim(result.errorMeta.spec)}`);
    if (result.errorMeta?.hint) lines.push(`  Hint:       ${yellow(result.errorMeta.hint)}`);
  }

  if (result._partialReason) {
    lines.push(`  ${yellow('Note:')}       ${result._partialReason}`);
  }

  lines.push('');
  lines.push(WAYFINDING);
  lines.push('');
  return lines.join('\n');
}

export function formatBundleResult(result, opts = {}) {
  const lines = [];
  const icon = result.valid ? green('✓') : red('✗');
  const status = result.valid ? green('VALID') : red('INVALID');
  lines.push(`\n${icon} Bundle: ${status}`);
  lines.push(`  Total:      ${result.total}`);
  lines.push(`  Passed:     ${green(String(result.passed))}`);
  lines.push(`  Failed:     ${result.failed > 0 ? red(String(result.failed)) : '0'}`);
  if (Array.isArray(result.errors) && result.errors.length > 0) {
    lines.push(`\n  ${red('Errors:')}`);
    for (const e of result.errors) lines.push(`    ${red('•')} ${e}`);
  }
  lines.push('');
  lines.push(WAYFINDING);
  lines.push('');
  return lines.join('\n');
}

/**
 * Render the salient-field lines for a recognized macro snapshot summary.
 *
 * @param {Object} s macroSummary object from engines/macro-snapshot.js
 * @returns {string[]}
 */
function macroSummaryLines(s) {
  const lines = [];
  if (s.description) lines.push(`  Snapshot:   ${dim(s.description)}`);
  if (s.as_of) lines.push(`  As of:      ${dim(s.as_of)}`);
  switch (s.schema) {
    case 'scopeblind.macro.market-state/1':
      lines.push(`  Class:      ${s.classification}${s.confidence !== undefined ? dim(` (confidence ${s.confidence})`) : ''}`);
      if (s.pillars) lines.push(`  Pillars:    ${dim(Object.entries(s.pillars).map(([k, v]) => `${k} ${v >= 0 ? '+' : ''}${v}`).join(', '))}`);
      break;
    case 'scopeblind.macro.regime-snapshot/1':
      lines.push(`  Regime:     ${s.regime}${s.candidate_regime && s.candidate_regime !== s.regime ? dim(` (candidate ${s.candidate_regime})`) : ''}`);
      if (s.liquidity_overlay) lines.push(`  Liquidity:  ${s.liquidity_overlay}`);
      if (s.confidence !== undefined) lines.push(`  Confidence: ${dim(String(s.confidence))}`);
      break;
    case 'scopeblind.macro.tape-snapshot/1':
      lines.push(`  Tape type:  ${s.tape_type}${s.material !== undefined ? dim(` (${s.material ? 'material' : 'immaterial'})`) : ''}`);
      if (s.coherence !== undefined) lines.push(`  Coherence:  ${dim(String(s.coherence))}`);
      if (s.attribution_tier) lines.push(`  Attributed: ${dim(s.attribution_tier)}`);
      break;
    case 'scopeblind.macro.vulnerability/1':
      if (s.regime || s.market_state) lines.push(`  Posture:    ${dim([s.regime, s.market_state].filter(Boolean).join(' / '))}`);
      if (Array.isArray(s.top_vulnerabilities) && s.top_vulnerabilities.length) {
        lines.push(`  Top risk:   ${dim(s.top_vulnerabilities.map((v) => `${v.factor} (pain ${v.pain})`).join(', '))}`);
      }
      break;
    case 'scopeblind.macro.alert/1':
      lines.push(`  Severity:   ${s.severity}${s.kind ? dim(` (${s.kind})`) : ''}`);
      if (s.title) lines.push(`  Title:      ${s.title}`);
      break;
    case 'scopeblind.macro.journal-entry/1':
      if (s.author) lines.push(`  Author:     ${s.author}`);
      lines.push(`  References: ${dim(`${s.reference_count} signed snapshot(s)`)}`);
      break;
    case 'scopeblind.macro.track-record-manifest/1':
      lines.push(`  Inventory:  ${dim(`${s.snapshot_count} snapshots, ${s.journal_count} journal entries`)}`);
      break;
    case 'scopeblind.macro.transparency-head/1':
      if (s.log_id) lines.push(`  Log:        ${dim(s.log_id)}`);
      lines.push(`  Tree size:  ${dim(`${s.tree_size} leaves`)}`);
      if (s.root_hash) lines.push(`  Root:       ${dim(`${String(s.root_hash).slice(0, 16)}...`)}`);
      break;
    case 'scopeblind.macro.transparency-witness/1':
      if (s.head_digest) lines.push(`  Head:       ${dim(`${String(s.head_digest).slice(0, 16)}...`)}`);
      lines.push(`  Tree size:  ${dim(`${s.tree_size} leaves`)}`);
      break;
    default:
      break;
  }
  return lines;
}

/**
 * Format a ScopeBlind Gate receipt-tuple result.
 *
 * The report states what a VALID result proves (authenticity and
 * integrity relative to the carried key) and what it does not
 * (correct computation, external corroboration, signer identity).
 *
 * @param {Object} result from src/engines/gate-receipt.js
 * @param {Object} opts cli options
 * @returns {string}
 */
export function formatGateTupleResult(result, opts = {}) {
  const lines = [];

  if (result.valid && result.publicKey && result.publicKey.length === 64 && !isCI && !opts.noSigil) {
    lines.push('');
    lines.push(renderTerminalSigil(result.publicKey));
  }

  const icon = result.valid ? green('✓') : red('✗');
  const status = result.valid ? green('VALID') : red('INVALID');
  lines.push(`\n${icon} Signature: ${status}`);
  lines.push(`  Format:     ${result.macroSchema ? 'ScopeBlind macro-engine snapshot' : 'ScopeBlind Gate receipt tuple'}`);
  if (result.schema) {
    const recog = result.macroSchema && result.schemaRecognized
      ? dim('(recognized macro schema)')
      : result.schemaRecognized
        ? dim('(recognized)')
        : yellow('(unrecognized schema; verified as a generic tuple)');
    lines.push(`  Schema:     ${result.schema} ${recog}`);
  } else {
    lines.push(`  Schema:     ${yellow('(none; verified as a generic tuple)')}`);
  }
  if (result.macroSummary) {
    for (const line of macroSummaryLines(result.macroSummary)) lines.push(line);
  }
  if (result.algorithm) lines.push(`  Algorithm:  ${result.algorithm} (over the SHA-256 payload digest)`);
  if (result.digest) lines.push(`  Digest:     ${dim(result.digest)}`);
  if (result.recomputedDigest) lines.push(`  Recomputed: ${red(result.recomputedDigest)}`);
  if (result.publicKey) lines.push(`  Signer:     ${result.signerLabel ? bold(result.signerLabel) + ' ' : ''}${dim(result.publicKey)}`);
  if (result.keySource) lines.push(`  Key:        ${result.keySource}`);
  if (result.publicKey) lines.push(trustTierLine(result));

  const pf = result.payloadFields || {};
  if (pf.decision) lines.push(`  Decision:   ${pf.decision}`);
  if (pf.proposal) {
    const p = [pf.proposal.side, pf.proposal.qty, pf.proposal.symbol].filter((v) => v !== undefined).join(' ');
    lines.push(`  Proposal:   ${p}`);
  }
  if (pf.symbol && !pf.proposal) lines.push(`  Instrument: ${[pf.side, pf.qty ?? pf.qty_ordered, pf.symbol].filter((v) => v !== undefined).join(' ')}`);
  if (pf.batch_id) lines.push(`  Batch:      ${pf.batch_id}${pf.leg_count !== undefined ? dim(` (${pf.leg_count} legs)`) : ''}`);
  if (pf.status) lines.push(`  Status:     ${pf.status}${pf.qty_filled !== undefined ? dim(` (${pf.qty_filled}/${pf.qty_ordered} filled)`) : ''}`);
  if (pf.approver) lines.push(`  Approver:   ${pf.approver}`);
  if (pf.source) lines.push(`  Source:     ${pf.source}`);
  if (pf.mandate_name) lines.push(`  Mandate:    ${pf.mandate_name}${pf.mandate_digest ? dim(` (${String(pf.mandate_digest).slice(0, 16)}...)`) : ''}`);
  if (pf.evaluated_at) lines.push(`  Evaluated:  ${dim(pf.evaluated_at)}`);
  if (pf.decided_at) lines.push(`  Decided:    ${dim(pf.decided_at)}`);
  if (pf.filled_at) lines.push(`  Filled:     ${dim(pf.filled_at)}`);

  if (result.chainFields) {
    lines.push(`  ${bold('Chain links carried (not checked standalone):')}`);
    for (const [k, v] of Object.entries(result.chainFields)) {
      lines.push(`    ${dim(`${k}: ${v}`)}`);
    }
    lines.push(`    ${dim('Verify the evidence bundle to check these links against their parents.')}`);
  }

  if (result.error && !result.valid) {
    lines.push(`  Error:      ${red(result.error)}`);
    if (result.detail) lines.push(`  Detail:     ${yellow(result.detail)}`);
    if (result.errorMeta?.hint) lines.push(`  Hint:       ${yellow(result.errorMeta.hint)}`);
  }

  if (result.valid && Array.isArray(result.proves)) {
    lines.push(`  ${bold('This proves:')}`);
    for (const p of result.proves) lines.push(`    ${green('•')} ${dim(p)}`);
    lines.push(`  ${bold('This does not prove:')}`);
    for (const l of (result.limitations || [])) lines.push(`    ${yellow('!')} ${dim(l)}`);
  }

  lines.push('');
  lines.push(WAYFINDING);
  lines.push('');
  return lines.join('\n');
}

/**
 * Format a Legate governed-receipt result: the flat, pipe-delimited action
 * receipt co-signed by the desktop daemon and the iPhone. The whole point is
 * that this is re-verified by the OPEN tool over the exact signed bytes, so the
 * output leads with the signer and the action identity, names what the kind is,
 * and is explicit about what an embedded key does and does not prove.
 *
 * @param {Object} result from src/engines/legate-governed-receipt.js
 * @param {Object} opts cli options
 * @returns {string}
 */
export function formatGovernedReceiptResult(result, opts = {}) {
  const lines = [];

  if (result.valid && result.publicKey && result.publicKey.length === 64 && !isCI && !opts.noSigil) {
    lines.push('');
    lines.push(renderTerminalSigil(result.publicKey));
  }

  const icon = result.valid ? green('✓') : red('✗');
  const status = result.valid ? green('VALID') : red('INVALID');
  lines.push(`\n${icon} Signature: ${status}`);
  lines.push(`  Format:     Legate governed receipt`);

  const kindLabel = result.kindRecognized ? `${result.kind} ${dim('(recognized governed action)')}` : `${result.kind} ${yellow('(unrecognized action kind)')}`;
  lines.push(`  Action:     ${kindLabel}`);

  const pf = result.payloadFields || {};
  if (pf.tool) lines.push(`  Tool:       ${pf.tool}`);
  if (pf.decision) lines.push(`  Decision:   ${pf.decision}`);
  if (pf.id) lines.push(`  Receipt id: ${dim(pf.id)}`);
  if (pf.input_sha256) lines.push(`  Input:      ${dim(`sha256:${String(pf.input_sha256).slice(0, 16)}…`)}`);
  if (pf.result_sha256) lines.push(`  Result:     ${dim(`sha256:${String(pf.result_sha256).slice(0, 16)}…`)}`);
  if (pf.at) lines.push(`  Signed at:  ${dim(pf.at)}`);
  if (result.algorithm) lines.push(`  Algorithm:  ${result.algorithm} ${dim('(over the canonical action payload, not a digest)')}`);
  if (result.publicKey) lines.push(`  Signer:     ${result.signerLabel ? bold(result.signerLabel) + ' ' : ''}${dim(result.publicKey)}`);
  if (result.keySource) lines.push(`  Key:        ${result.keySource}`);
  if (result.publicKey) lines.push(trustTierLine(result));

  // Restraint receipts: surface WHAT was prevented and re-verify that the
  // disclosed detail binds to the signed hashes. This is the negative-space
  // proof: most governance can only show what an agent did; this shows, offline
  // and position-blind, what it was stopped from doing and why.
  if (result.valid && result.restraint) {
    const rb = result.restraint;
    lines.push('');
    lines.push(`  ${bold('Prevented:')}  ${dim('an out-of-mandate action the gate blocked before it could execute')}`);
    if (rb.risk_band) lines.push(`    Risk band:     ${rb.risk_band}`);
    if (rb.determining.length) lines.push(`    Blocked by:    ${rb.determining.join(', ')}`);
    if (rb.proposed) {
      const p = rb.proposed;
      const notional = typeof p.notional === 'number' ? ` ${dim(`($${p.notional.toLocaleString('en-US')})`)}` : '';
      lines.push(`    Blocked order: ${[p.side, p.qty, p.symbol].filter((x) => x != null && x !== '').join(' ')}${notional}`);
    } else {
      lines.push(`    Blocked order: ${dim('withheld (position-blind)')}`);
    }
    lines.push(`    ${rb.outcome_bound ? green('✓') : red('✗')} the outcome above re-hashes to the signed result hash`);
    if (rb.proposed_bound === null) {
      lines.push(`    ${green('✓')} the blocked order is salt-committed to the signed input hash ${dim('(openable to a regulator)')}`);
    } else {
      lines.push(`    ${rb.proposed_bound ? green('✓') : red('✗')} the disclosed order re-hashes (under its salt) to the signed input hash`);
    }
  }

  if (result.error && !result.valid) {
    lines.push(`  Error:      ${red(result.error)}`);
    if (result.error === 'invalid_signature') lines.push(`  Detail:     ${yellow('the signed bytes were altered or the key does not match — this receipt was tampered with')}`);
    else if (result.detail) lines.push(`  Detail:     ${yellow(result.detail)}`);
    if (result.expectedKey) lines.push(`  Expected:   ${yellow(result.expectedKey)} ${dim('(--key)')}`);
  }

  if (result.valid && Array.isArray(result.proves)) {
    lines.push(`  ${bold('This proves:')}`);
    for (const p of result.proves) lines.push(`    ${green('•')} ${dim(p)}`);
    lines.push(`  ${bold('This does not prove:')}`);
    for (const l of (result.limitations || [])) lines.push(`    ${yellow('!')} ${dim(l)}`);
  }

  lines.push('');
  lines.push(WAYFINDING);
  lines.push('');
  return lines.join('\n');
}

/**
 * Format a Trusted Context Pack result: the signed attestation that a source file
 * parsed to this context at this confidence and freshness. The output leads with
 * the signer and the gate decision (usable / needs approval / blocked), names the
 * source type, and is explicit that this attests the parse, not the provenance.
 *
 * @param {Object} result from src/engines/trusted-context-pack.js
 * @param {Object} opts cli options
 * @returns {string}
 */
export function formatTrustedContextPackResult(result, opts = {}) {
  const lines = [];

  if (result.valid && result.publicKey && result.publicKey.length === 64 && !isCI && !opts.noSigil) {
    lines.push('');
    lines.push(renderTerminalSigil(result.publicKey));
  }

  const icon = result.valid ? green('✓') : red('✗');
  const status = result.valid ? green('VALID') : red('INVALID');
  lines.push(`\n${icon} Signature: ${status}`);
  lines.push(`  Format:     ScopeBlind Trusted Context Pack`);
  if (result.schema) {
    lines.push(`  Schema:     ${result.schema} ${result.schemaRecognized ? dim('(recognized)') : yellow('(unrecognized)')}`);
  }

  const pf = result.payloadFields || {};
  if (pf.source_type) lines.push(`  Source:     ${pf.source_type}${pf.source_format ? dim(` (${pf.source_format})`) : ''}`);
  if (pf.file_name) lines.push(`  File:       ${pf.file_name}`);
  if (pf.file_hash) lines.push(`  File hash:  ${dim(`sha256:${String(pf.file_hash).slice(0, 16)}…`)}`);

  // The gate decision is the headline: usable feeds a decision, the others do not.
  const gate = result.gateStatus || pf.gate_status;
  if (gate) {
    const tone = gate === 'usable' ? green(gate) : gate === 'needs_approval' ? yellow(gate) : red(gate);
    const note = gate === 'usable' ? 'may feed a gate decision'
      : gate === 'needs_approval' ? 'held: requires explicit human approval before use'
      : 'blocked: cannot feed a decision';
    lines.push(`  Gate:       ${tone} ${dim(`(${note})`)}`);
  }
  if (result.confidence !== undefined) lines.push(`  Confidence: ${result.confidence}`);
  if (pf.freshness) {
    const dated = pf.freshness.as_of ? `as of ${String(pf.freshness.as_of).slice(0, 10)}` : yellow('no as-of date');
    const fresh = pf.freshness.stale ? red('(stale)') : dim('(fresh)');
    lines.push(`  Freshness:  ${dated} ${fresh}`);
  }
  if (Array.isArray(pf.warnings) && pf.warnings.length) {
    lines.push(`  ${bold('Warnings:')}`);
    for (const w of pf.warnings) lines.push(`    ${yellow('!')} ${dim(w)}`);
  }
  if (result.algorithm) lines.push(`  Algorithm:  ${result.algorithm} ${dim('(over the SHA-256 payload digest)')}`);
  if (result.digest) lines.push(`  Digest:     ${dim(result.digest)}`);
  if (result.recomputedDigest) lines.push(`  Recomputed: ${red(result.recomputedDigest)}`);
  if (result.publicKey) lines.push(`  Signer:     ${result.signerLabel ? bold(result.signerLabel) + ' ' : ''}${dim(result.publicKey)}`);
  if (result.keySource) lines.push(`  Key:        ${result.keySource}`);
  if (result.publicKey) lines.push(trustTierLine(result));

  if (result.error && !result.valid) {
    lines.push(`  Error:      ${red(result.error)}`);
    if (result.error === 'invalid_signature') lines.push(`  Detail:     ${yellow('the signed bytes were altered or the key does not match; this pack was tampered with')}`);
    else if (result.detail) lines.push(`  Detail:     ${yellow(result.detail)}`);
    if (result.expectedKey) lines.push(`  Expected:   ${yellow(result.expectedKey)} ${dim('(--key)')}`);
  }

  if (result.valid && Array.isArray(result.proves)) {
    lines.push(`  ${bold('This proves:')}`);
    for (const p of result.proves) lines.push(`    ${green('•')} ${dim(p)}`);
    lines.push(`  ${bold('This does not prove:')}`);
    for (const l of (result.limitations || [])) lines.push(`    ${yellow('!')} ${dim(l)}`);
  }

  lines.push('');
  lines.push(WAYFINDING);
  lines.push('');
  return lines.join('\n');
}

/**
 * Format a ScopeBlind Gate evidence-bundle result. Crypto failures
 * and chain failures are reported separately so a reader can tell
 * "this record was forged or modified" apart from "this record is
 * authentic but points at the wrong parent".
 *
 * @param {Object} result from src/engines/gate-receipt.js
 * @param {Object} opts cli options
 * @returns {string}
 */
export function formatGateBundleResult(result, opts = {}) {
  const lines = [];
  const icon = result.valid ? green('✓') : red('✗');
  const status = result.valid ? green('VALID') : red('INVALID');
  lines.push(`\n${icon} Gate evidence bundle: ${status}`);
  lines.push(`  Schema:      ${result.schema || '(missing)'}`);
  if (result.exportedAt) lines.push(`  Exported:    ${dim(result.exportedAt)}`);
  lines.push(`  Entries:     ${result.entryCount}`);
  lines.push(`  Records:     ${result.total} (${green(String(result.passed))} passed, ${result.failed > 0 ? red(String(result.failed)) : '0'} failed)`);
  const cryptoOk = result.total - result.cryptoFailed;
  lines.push(`  Signatures:  ${result.cryptoFailed > 0 ? red(`${cryptoOk}/${result.total} valid`) : green(`${cryptoOk}/${result.total} valid`)}`);
  const chainOk = result.chainChecks - result.chainFailed;
  lines.push(`  Chain links: ${result.chainFailed > 0 ? red(`${chainOk}/${result.chainChecks} consistent`) : green(`${chainOk}/${result.chainChecks} consistent`)}`);
  if (result.manifestValid !== null) lines.push(`  Signed manifest: ${result.manifestValid ? green('valid and exact') : red('missing or inconsistent')}`);

  const unrecognized = (result.records || []).filter((r) => !r.schemaRecognized);
  if (unrecognized.length > 0) {
    lines.push(`  ${yellow('Unrecognized schemas:')} ${[...new Set(unrecognized.map((r) => r.schema || '(none)'))].join(', ')} ${dim('(verified as generic tuples)')}`);
  }

  if (Array.isArray(result.signers) && result.signers.length > 0) {
    lines.push(`  ${bold('Signing keys seen:')}`);
    for (const s of result.signers) {
      const tag = s.isGateKey ? green('gate key') : yellow('other key');
      lines.push(`    ${dim(s.key)} ${tag} ${dim(`(${s.roles.join(', ')})`)}`);
    }
  }
  if (result.entriesUseGateKey !== null) {
    lines.push(`  Entry receipts signed by gate_verification_key: ${result.entriesUseGateKey ? green('yes') : red('no')}`);
  }

  if (Array.isArray(result.errors) && result.errors.length > 0) {
    lines.push(`\n  ${red('Failures:')} ${dim('([crypto] record forged or modified; [chain] record authentic but link inconsistent)')}`);
    for (const e of result.errors) lines.push(`    ${red('•')} ${e}`);
  }

  if (result.valid) {
    lines.push('');
    lines.push(`  ${bold('This proves:')}`);
    for (const p of (result.proves || [])) lines.push(`    ${green('•')} ${dim(p)}`);
    lines.push(`  ${bold('This does not prove:')}`);
    for (const l of (result.limitations || [])) lines.push(`    ${yellow('!')} ${dim(l)}`);
  }

  lines.push('');
  lines.push(WAYFINDING);
  lines.push('');
  return lines.join('\n');
}

/**
 * Format a ScopeBlind macro-engine track-record bundle result. Like the Gate
 * bundle formatter, crypto failures and chain (single-signer / manifest /
 * history) failures are reported separately.
 *
 * @param {Object} result from src/engines/macro-snapshot.js
 * @param {Object} opts cli options
 * @returns {string}
 */
export function formatMacroTrackRecordResult(result, opts = {}) {
  const lines = [];
  const icon = result.valid ? green('✓') : red('✗');
  const status = result.valid ? green('VALID') : red('INVALID');
  lines.push(`\n${icon} Macro track-record bundle: ${status}`);
  lines.push(`  Schema:      ${result.schema || '(missing)'}`);
  if (result.exportedAt) lines.push(`  Exported:    ${dim(result.exportedAt)}`);
  if (result.period) lines.push(`  Period:      ${dim(`${result.period.from} → ${result.period.to}`)}`);
  if (result.custody) lines.push(`  Custody:     ${dim(result.custody)}`);
  lines.push(`  Identity:    ${result.signerPinned ? green('pinned expected key') : yellow('embedded key only — integrity, not operator identity')}`);
  if (result.sequence) lines.push(`  Sequence:    ${result.sequence}`);
  lines.push(`  Snapshots:   ${result.snapshotCount}`);
  lines.push(`  Journal:     ${result.journalCount}`);
  lines.push(`  Records:     ${result.total} (${green(String(result.passed))} passed, ${result.failed > 0 ? red(String(result.failed)) : '0'} failed)`);
  const cryptoOk = result.total - result.cryptoFailed;
  lines.push(`  Signatures:  ${result.cryptoFailed > 0 ? red(`${cryptoOk}/${result.total} valid`) : green(`${cryptoOk}/${result.total} valid`)}`);
  const chainOk = result.chainChecks - result.chainFailed;
  lines.push(`  Chain links: ${result.chainFailed > 0 ? red(`${chainOk}/${result.chainChecks} consistent`) : green(`${chainOk}/${result.chainChecks} consistent`)}`);
  if (result.manifestValid !== null) lines.push(`  Signed manifest: ${result.manifestValid ? green('valid and exact') : red('missing or inconsistent')}`);
  lines.push(`  Single-key consistency: ${result.singleSigner ? green('yes') : red('no')}`);
  lines.push(`  Append-only history: ${result.historyChainValid === true ? green('linked and retained') : result.historyChainValid === false ? red('invalid') : yellow('not established by this export')}`);
  lines.push(`  Signed checkpoint: ${result.historyAnchored ? green('present') : yellow('absent')}`);
  if (result.transparencyAnchor) {
    const t = result.transparencyAnchor;
    const leaves = t.tree_size !== null ? `${t.tree_size} leaves` : 'Merkle log';
    if (t.anchor === 'witnessed') lines.push(`  Transparency: ${green(`witness-anchored (Merkle log, ${leaves})`)}`);
    else if (t.anchor === 'self_signed') lines.push(`  Transparency: ${yellow(`self-signed (Merkle log, ${leaves})`)}`);
    else lines.push(`  Transparency: ${red('not anchored')}`);
  }
  if (result.historyHeadPinned) lines.push(`  History head: ${green('matches independently pinned head')}`);
  if (result.anchorHeadPinned) lines.push(`  Anchor head:  ${green('matches independently pinned head')}`);

  if (Array.isArray(result.signers) && result.signers.length > 0) {
    lines.push(`  ${bold('Signing keys seen:')}`);
    for (const s of result.signers) {
      const tag = s.isModelKey ? green('model key') : yellow('other key');
      lines.push(`    ${dim(s.key)} ${tag} ${dim(`(${s.roles.join(', ')})`)}`);
    }
  }

  if (Array.isArray(result.errors) && result.errors.length > 0) {
    lines.push(`\n  ${red('Failures:')} ${dim('([crypto] record forged or modified; [chain] custody, manifest, or history-head inconsistent)')}`);
    for (const e of result.errors) lines.push(`    ${red('•')} ${e}`);
  }

  if (result.valid) {
    lines.push('');
    lines.push(`  ${bold('This proves:')}`);
    for (const p of (result.proves || [])) lines.push(`    ${green('•')} ${dim(p)}`);
    lines.push(`  ${bold('This does not prove:')}`);
    for (const l of (result.limitations || [])) lines.push(`    ${yellow('!')} ${dim(l)}`);
  }

  lines.push('');
  lines.push(WAYFINDING);
  lines.push('');
  return lines.join('\n');
}

export function formatKuResult(result, opts = {}) {
  const lines = [];
  const icon = result.valid ? green('✓') : red('✗');
  const status = result.valid ? green('VALID') : red('INVALID');
  lines.push(`\n${icon} Knowledge Unit: ${status}`);
  if (result.topic) lines.push(`  Topic:        "${result.topic}"`);
  if (result.totalReceipts !== undefined) {
    lines.push(`  Receipts:     ${result.verifiedReceipts}/${result.totalReceipts} verified`);
  }
  if (result.models) lines.push(`  Models:       ${result.models.join(', ')}`);
  if (result.rounds) lines.push(`  Rounds:       ${result.rounds}`);
  if (result.consensusLevel) lines.push(`  Consensus:    ${result.consensusLevel}`);
  if (result.dissentingModels && result.dissentingModels.length > 0) {
    lines.push(`  Dissent:      ${result.dissentingModels.join(', ')} (explicitly recorded)`);
  }
  if (result.tier) lines.push(`  Tier:         ${result.tier.label}`);
  lines.push(`  Protocol:     ${dim('draft-farley-acta-knowledge-units-00')}`);
  if (result.errors) {
    lines.push(`\n  ${red('Errors:')}`);
    for (const e of result.errors) lines.push(`    ${red('•')} ${e}`);
  }
  lines.push('');
  lines.push(WAYFINDING);
  lines.push('');
  return lines.join('\n');
}

export function formatSelfCheckResult(r) {
  const lines = [];
  if (r.canonical) {
    lines.push('');
    lines.push(`  ${green('✓')} Monitored verifier source matches bundled commitment — ${green(r.name || 'unnamed')}`);
    lines.push(`    Sigil:    ${teal(r.fingerprint || '—')}`);
    lines.push(`    Version:  ${r.version || '—'}`);
    lines.push(`    Package:  ${r.pkg || '—'}`);
    lines.push(`    Source:   ${dim((r.installedSourceHash || '').slice(0, 16) + '...')} ${green('matches commitment')}`);
    lines.push(`    Policy:   ${green('matches commitment')}`);
    lines.push(`    Sigil:    ${green('matches commitment')}`);
    lines.push('');
    lines.push(`  ${dim('This is a public, locally recomputable integrity check.')}`);
    lines.push(`  ${dim('It is not a project signature, publisher attestation, or independent witness.')}`);
  } else {
    lines.push(`\n  ${red('✗')} Monitored verifier source does not match the bundled commitment\n`);
    if (!r.sourceMatches) {
      lines.push(`    Source:   ${red('MISMATCH')}`);
      lines.push(`      Installed: ${(r.installedSourceHash || '').slice(0, 32)}...`);
      lines.push(`      Expected:  ${(r.committedSourceHash || '').slice(0, 32)}...`);
    }
    if (!r.policyMatches) lines.push(`    Policy:   ${red('MISMATCH')} — sigil.json may have been tampered with`);
    if (!r.sigilMatches) lines.push(`    Sigil:    ${red('MISMATCH')} — the commitment chain is broken`);
    lines.push('');
    lines.push(`  ${yellow('The installed bytes differ from the commitment bundled with this copy.')}`);
    lines.push(`  ${yellow('It may be a fork, a development build, or a tampered copy.')}`);
    lines.push(`  ${dim('Reinstall from your independently pinned package source and compare again.')}`);
  }
  lines.push('');
  return lines.join('\n');
}
