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
    lines.push(renderTerminalSigil(r.projectPublicKey || ''));
    lines.push('');
    lines.push(`  ${green('✓')} Canonical verifier — ${green(r.name || 'unnamed')}`);
    lines.push(`    Sigil:    ${teal(r.fingerprint || '—')}`);
    lines.push(`    Version:  ${r.version || '—'}`);
    lines.push(`    Package:  ${r.pkg || '—'}`);
    lines.push(`    Source:   ${dim((r.installedSourceHash || '').slice(0, 16) + '...')} ${green('matches commitment')}`);
    lines.push(`    Policy:   ${green('matches commitment')}`);
    lines.push(`    Sigil:    ${green('matches commitment')}`);
    lines.push('');
    lines.push(`  ${dim('This verifier is the unmodified canonical release.')}`);
    lines.push(`  ${dim('The source code has not been changed since it was published.')}`);
  } else {
    lines.push(`\n  ${red('✗')} Modified verifier — NOT the canonical release\n`);
    if (!r.sourceMatches) {
      lines.push(`    Source:   ${red('MISMATCH')}`);
      lines.push(`      Installed: ${(r.installedSourceHash || '').slice(0, 32)}...`);
      lines.push(`      Expected:  ${(r.committedSourceHash || '').slice(0, 32)}...`);
    }
    if (!r.policyMatches) lines.push(`    Policy:   ${red('MISMATCH')} — sigil.json may have been tampered with`);
    if (!r.sigilMatches) lines.push(`    Sigil:    ${red('MISMATCH')} — the commitment chain is broken`);
    lines.push('');
    lines.push(`  ${yellow('This verifier has been modified since the canonical release.')}`);
    lines.push(`  ${yellow('It may be a fork, a development build, or a tampered copy.')}`);
    lines.push(`  ${dim('Get the canonical verifier: npm install @veritasacta/verify')}`);
  }
  lines.push('');
  return lines.join('\n');
}
