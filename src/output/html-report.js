/**
 * HTML audit report generator.
 *
 * Produces a single self-contained HTML file suitable for delivery to
 * an auditor, compliance team, or counterparty. Contains verification
 * summary, per-receipt breakdown, Sigil attestation, and all the
 * provenance metadata needed to independently re-verify.
 *
 * The HTML file is safe to email, publish, or print. It contains no
 * external resources (styles are inline, no JS), renders in any modern
 * browser, and includes the raw JSON of the verification result for
 * programmatic re-use.
 *
 * @module verify-cli/src/output/html-report
 * @license Apache-2.0
 */

/**
 * Escape a string for safe HTML inclusion.
 * @param {string|number|boolean|null|undefined} s
 * @returns {string}
 */
function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Render the HTML audit report.
 *
 * @param {Object} args
 * @param {Object} args.result         bulk or single verification result
 * @param {Object} args.sigil          parsed sigil.json
 * @param {Object} [args.attestation]  canonical attestation (optional)
 * @param {string} [args.title]        report title
 * @returns {string}
 */
export function renderHtmlReport({ result, sigil, attestation, title }) {
  const reportTitle = title || 'Veritas Acta verification report';
  const generatedAt = new Date().toISOString();

  const isBulk = result.total !== undefined;
  const bulkSummary = isBulk ? `
    <table>
      <tr><th>Total</th><td>${result.total}</td></tr>
      <tr><th>Verified</th><td class="pass">${result.verified || result.passed || 0}</td></tr>
      <tr><th>Failed</th><td class="fail">${result.failed || 0}</td></tr>
      <tr><th>Chain breaks</th><td>${result.chainBreaks || 0}</td></tr>
    </table>
  ` : `
    <table>
      <tr><th>Valid</th><td class="${result.valid ? 'pass' : 'fail'}">${result.valid ? 'YES' : 'NO'}</td></tr>
      <tr><th>Format</th><td>${esc(result.format)}</td></tr>
      <tr><th>Mode</th><td>${esc(result.modeLabel || result.format)}</td></tr>
      <tr><th>Algorithm</th><td>${esc(result.algorithm)}</td></tr>
      <tr><th>Kid</th><td><code>${esc(result.kid)}</code></td></tr>
      <tr><th>Tier</th><td>${esc(result.tier?.label || '—')}</td></tr>
      ${result.error ? `<tr><th>Error</th><td class="fail">${esc(result.error)}</td></tr>` : ''}
    </table>
  `;

  const perReceipt = isBulk && result.receipts ? `
    <h2>Per-receipt results</h2>
    <table>
      <tr><th>Index</th><th>Valid</th><th>Tier</th><th>Type</th><th>Kid</th><th>Error</th></tr>
      ${result.receipts.slice(0, 500).map((r) => `
        <tr>
          <td>${r.index ?? ''}</td>
          <td class="${r.valid ? 'pass' : 'fail'}">${r.valid ? '✓' : '✗'}</td>
          <td>T${r.tier ?? '—'}</td>
          <td>${esc(r.type ?? '—')}</td>
          <td><code>${esc(r.kid ?? '—')}</code></td>
          <td class="fail">${esc(r.error ?? '')}</td>
        </tr>
      `).join('')}
    </table>
    ${result.receipts.length > 500 ? `<p class="truncated">… ${result.receipts.length - 500} more receipts truncated from report (full data in raw JSON section below).</p>` : ''}
  ` : '';

  const attestationBlock = attestation ? `
    <h2>Canonical attestation</h2>
    <pre>${esc(JSON.stringify(attestation, null, 2))}</pre>
    <p class="note">Publish this attestation to demonstrate the verifier was canonical at the time of this report.</p>
  ` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${esc(reportTitle)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 32px auto; padding: 0 24px; color: #1f2937; line-height: 1.55; }
    h1 { font-size: 24px; margin-bottom: 4px; }
    h2 { font-size: 18px; margin-top: 32px; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }
    .meta { color: #6b7280; font-size: 13px; }
    table { border-collapse: collapse; width: 100%; margin-top: 12px; }
    th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #e5e7eb; font-size: 13px; vertical-align: top; }
    th { background: #f9fafb; font-weight: 600; width: 180px; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; background: #f3f4f6; padding: 1px 4px; border-radius: 3px; }
    pre { background: #f3f4f6; border: 1px solid #e5e7eb; border-radius: 4px; padding: 12px; font-size: 11px; overflow-x: auto; }
    .pass { color: #059669; font-weight: 600; }
    .fail { color: #dc2626; font-weight: 600; }
    .sigil { font-family: monospace; font-size: 11px; line-height: 1.1; white-space: pre; color: #0d6e6e; background: #ecfdf5; padding: 12px; border-radius: 4px; border: 1px solid #a7f3d0; display: inline-block; }
    .note { color: #6b7280; font-size: 12px; }
    .truncated { color: #92400e; font-size: 12px; font-style: italic; }
    footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid #e5e7eb; color: #6b7280; font-size: 12px; }
    footer a { color: #0d6e6e; text-decoration: none; }
    footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>${esc(reportTitle)}</h1>
  <p class="meta">Generated by <code>@veritasacta/verify@${esc(sigil?.policy?.package_version || '0.5.0')}</code> · Sigil ${esc(sigil?.name || '—')} (${esc(sigil?.fingerprint || '—')}) · ${esc(generatedAt)}</p>

  <h2>Summary</h2>
  ${bulkSummary}

  ${perReceipt}

  ${attestationBlock}

  <h2>Verifier provenance</h2>
  <table>
    <tr><th>Sigil fingerprint</th><td><code>${esc(sigil?.fingerprint)}</code></td></tr>
    <tr><th>Sigil name</th><td>${esc(sigil?.name)}</td></tr>
    <tr><th>Verifier version</th><td>${esc(sigil?.policy?.package_version)}</td></tr>
    <tr><th>Verifier package</th><td>${esc(sigil?.policy?.package)}</td></tr>
    <tr><th>IETF draft target</th><td>${esc(sigil?.policy?.ietf_draft)}</td></tr>
    <tr><th>Source hash</th><td><code>${esc(sigil?.policy?.source_hash)}</code></td></tr>
  </table>

  <h2>Raw verification result (JSON)</h2>
  <pre>${esc(JSON.stringify(result, null, 2))}</pre>

  <footer>
    Protocol: <a href="https://veritasacta.com">veritasacta.com</a> · Managed receipts: <a href="https://scopeblind.com">scopeblind.com</a> · Apache-2.0
  </footer>
</body>
</html>`;
}
