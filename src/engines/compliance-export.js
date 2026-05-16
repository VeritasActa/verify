/**
 * @veritasacta/verify — compliance export engine
 *
 * Given a directory of signed decision receipts, produce evidence
 * bundles shaped for three compliance frameworks:
 *
 *   - SOC 2 Trust Services Criteria (CC6 Logical Access,
 *     CC7 System Operations, CC8 Change Management)
 *   - ISO/IEC 42001 (AI Management System) — A.6, A.8 controls
 *   - EU AI Act Article 12 (record-keeping) + Article 13 (transparency)
 *
 * The engine does NOT verify receipts itself; it assumes they have
 * already been verified by the main CLI. Its job is to bucket receipts
 * into control-mapped evidence artifacts, compute summary statistics,
 * and emit a portable JSON bundle plus a human-readable HTML report.
 *
 * Auditors get:
 *   - One signed manifest bundle.json + per-control CSVs
 *   - An HTML report with control names, evidence counts, timeline
 *
 * This is a v0 implementation. v1 will add control-specific rulesets
 * and auditor sign-off receipts.
 *
 * @module verify-cli/src/engines/compliance-export
 * @license Apache-2.0
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

// ───── Framework mappings ─────

/**
 * SOC 2 Trust Services Criteria that can be evidenced by decision
 * receipts produced by AI agent runtimes.
 *
 * Mapping strategy: each control lists tool-action patterns (as
 * case-insensitive substrings) that, when present in a receipt's
 * action field, provide evidence for that control.
 */
const SOC2_CONTROLS = {
  'CC6.1': {
    name: 'Logical and Physical Access Controls',
    description:
      'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.',
    actions: ['Read', 'Write', 'Edit', 'Bash', 'mcp:', 'tool:'],
    policy_field: 'decision',
  },
  'CC6.6': {
    name: 'Logical Access Restrictions',
    description:
      'The entity implements logical access security measures to protect against threats from sources outside its system boundaries.',
    actions: ['WebFetch', 'WebSearch', 'http', 'network:'],
    policy_field: 'decision',
  },
  'CC7.2': {
    name: 'Detection of Events',
    description:
      'The entity monitors system components and the operation of controls to detect anomalies that are indicative of malicious acts, natural disasters, and errors.',
    actions: ['anomaly', 'policy_violation', 'denied'],
    policy_field: 'decision',
  },
  'CC8.1': {
    name: 'Change Management',
    description:
      'The entity authorizes, designs, develops, configures, tests, approves, and implements changes to infrastructure, data, software.',
    actions: ['Write', 'Edit', 'commit', 'deploy'],
    policy_field: 'action',
  },
};

const ISO42001_CONTROLS = {
  'A.6.1.2': {
    name: 'AI System Impact Assessment',
    description:
      'The organization shall assess and document AI system impact throughout the lifecycle.',
    actions: ['decision', 'impact:', 'assessment:'],
    policy_field: 'type',
  },
  'A.8.2.1': {
    name: 'System Transparency',
    description:
      'Decisions made by or with AI systems shall be transparent and traceable.',
    actions: ['decision', 'tool:', 'action:'],
    policy_field: 'type',
  },
  'A.8.3.1': {
    name: 'Logging and Monitoring',
    description:
      'The organization shall ensure appropriate logging of AI system operations.',
    actions: ['*'],
    policy_field: 'type',
  },
  'A.9.2.1': {
    name: 'AI System Change Control',
    description:
      'Changes to AI systems shall be controlled, documented, and reviewed.',
    actions: ['Write', 'Edit', 'deploy', 'config:'],
    policy_field: 'action',
  },
};

const EU_AI_ACT_CONTROLS = {
  'Art.12(1)': {
    name: 'Automatic Recording of Events',
    description:
      'High-risk AI systems shall technically allow for the automatic recording of events (logs) over the duration of their lifetime.',
    actions: ['*'],
    policy_field: 'type',
  },
  'Art.12(2)': {
    name: 'Traceability of Functioning',
    description:
      'The logging capabilities shall ensure a level of traceability appropriate to the intended purpose.',
    actions: ['decision', 'chain:'],
    policy_field: 'type',
  },
  'Art.13(1)': {
    name: 'Transparency to Users',
    description:
      'High-risk AI systems shall be designed and developed in such a way as to ensure their operation is sufficiently transparent.',
    actions: ['decision', 'action:'],
    policy_field: 'type',
  },
  'Art.14(1)': {
    name: 'Human Oversight',
    description:
      'High-risk AI systems shall be designed and developed such that they can be effectively overseen by natural persons.',
    actions: ['human_review', 'approved_by', 'denied'],
    policy_field: 'decision',
  },
};

const FRAMEWORKS = {
  soc2:     { name: 'SOC 2 Trust Services Criteria',      controls: SOC2_CONTROLS },
  iso42001: { name: 'ISO/IEC 42001:2023',                 controls: ISO42001_CONTROLS },
  'eu-ai-act': { name: 'EU AI Act (Regulation 2024/1689)', controls: EU_AI_ACT_CONTROLS },
};

/**
 * @typedef {Object} ExportOptions
 * @property {string} receiptsDir           Path to directory of *.json receipts.
 * @property {'soc2'|'iso42001'|'eu-ai-act'|'all'} framework
 * @property {string} [startDate]           ISO-8601 date-time — inclusive lower bound.
 * @property {string} [endDate]             ISO-8601 date-time — exclusive upper bound.
 * @property {string} [organizationName]    Appears in the manifest and HTML header.
 */

/**
 * @typedef {Object} ExportResult
 * @property {Object} manifest              Summary manifest (JSON-serialisable).
 * @property {Object<string, Object[]>} evidence_by_control  Map control-id → matched receipts (summaries).
 * @property {string[]} warnings
 */

/**
 * Produce a compliance evidence bundle from a directory of receipts.
 *
 * @param {ExportOptions} opts
 * @returns {ExportResult}
 */
export function exportCompliance(opts) {
  const {
    receiptsDir,
    framework = 'all',
    startDate,
    endDate,
    organizationName = '(unspecified)',
  } = opts;

  const dir = resolve(receiptsDir);
  const frameworks =
    framework === 'all'
      ? Object.entries(FRAMEWORKS)
      : [[framework, FRAMEWORKS[framework]]];

  if (!FRAMEWORKS[framework] && framework !== 'all') {
    throw new Error(`unknown_framework:${framework}`);
  }

  const warnings = [];
  const receipts = loadReceipts(dir, warnings);
  const filtered = filterByWindow(receipts, startDate, endDate);

  const evidenceByControl = {};
  const stats = {};

  for (const [fwId, fwDef] of frameworks) {
    if (!fwDef) continue;
    stats[fwId] = { framework: fwDef.name, controls: {} };
    for (const [ctrlId, ctrl] of Object.entries(fwDef.controls)) {
      const matches = matchReceipts(filtered, ctrl);
      const key = `${fwId}:${ctrlId}`;
      evidenceByControl[key] = matches.map(summariseReceipt);
      stats[fwId].controls[ctrlId] = {
        name: ctrl.name,
        description: ctrl.description,
        evidence_count: matches.length,
        first_event: matches[0] ? matches[0].payload.issued_at : null,
        last_event: matches[matches.length - 1]
          ? matches[matches.length - 1].payload.issued_at
          : null,
      };
    }
  }

  const manifest = {
    format: 'veritasacta-compliance-export/v0',
    generated_at: new Date().toISOString(),
    organization: organizationName,
    receipts_scanned: receipts.length,
    receipts_in_window: filtered.length,
    window: { start: startDate || null, end: endDate || null },
    frameworks: stats,
  };

  return {
    manifest,
    evidence_by_control: evidenceByControl,
    warnings,
  };
}

/**
 * Render the export as a self-contained HTML audit report.
 * Returns a UTF-8 HTML string.
 *
 * @param {ExportResult} result
 * @returns {string}
 */
export function renderComplianceHTML(result) {
  const { manifest, evidence_by_control, warnings } = result;
  const esc = (s) =>
    String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');

  let html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Compliance Evidence Bundle — ${esc(manifest.organization)}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #111; line-height: 1.5; }
  h1 { margin-bottom: 0.25rem; }
  h2 { margin-top: 2.5rem; border-bottom: 1px solid #ddd; padding-bottom: 0.5rem; }
  h3 { margin-top: 2rem; }
  .meta { color: #666; margin-bottom: 2rem; font-size: 0.95rem; }
  .control { border: 1px solid #eee; border-radius: 6px; padding: 1rem 1.25rem; margin: 0.75rem 0; }
  .ctrl-head { display: flex; justify-content: space-between; align-items: baseline; }
  .count { font-variant-numeric: tabular-nums; font-weight: 600; color: #0a5; }
  .count.zero { color: #999; }
  .desc { color: #333; font-size: 0.9rem; margin: 0.5rem 0; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-top: 0.5rem; }
  th, td { text-align: left; padding: 0.25rem 0.5rem; border-bottom: 1px solid #f3f3f3; }
  th { background: #fafafa; color: #666; font-weight: 600; }
  .warn { background: #fff7e6; border-left: 3px solid #f90; padding: 0.5rem 0.75rem; margin: 1rem 0;
          font-size: 0.9rem; color: #774400; }
</style>
</head><body>
<h1>Compliance Evidence Bundle</h1>
<div class="meta">
  Organization: <strong>${esc(manifest.organization)}</strong><br/>
  Generated: ${esc(manifest.generated_at)}<br/>
  Receipts scanned: ${manifest.receipts_scanned} &middot; in window: ${manifest.receipts_in_window}<br/>
  Window: ${esc(manifest.window.start || '(beginning)')} &rarr; ${esc(manifest.window.end || '(end)')}
</div>
`;

  if (warnings.length) {
    html += `<div class="warn"><strong>Warnings:</strong><ul>`;
    for (const w of warnings) html += `<li>${esc(w)}</li>`;
    html += `</ul></div>`;
  }

  for (const [fwId, fw] of Object.entries(manifest.frameworks)) {
    html += `<h2>${esc(fw.framework)}</h2>`;
    for (const [ctrlId, ctrl] of Object.entries(fw.controls)) {
      const zero = ctrl.evidence_count === 0 ? ' zero' : '';
      html += `<div class="control">
        <div class="ctrl-head">
          <h3>${esc(ctrlId)} — ${esc(ctrl.name)}</h3>
          <div class="count${zero}">${ctrl.evidence_count} receipt(s)</div>
        </div>
        <div class="desc">${esc(ctrl.description)}</div>`;
      if (ctrl.evidence_count > 0) {
        html += `<div class="desc"><small>First: ${esc(ctrl.first_event || '')} &middot; Last: ${esc(ctrl.last_event || '')}</small></div>`;
        const evid = evidence_by_control[`${fwId}:${ctrlId}`] || [];
        const sample = evid.slice(0, 10);
        html += `<table>
          <thead><tr><th>issued_at</th><th>action</th><th>decision</th><th>kid</th><th>hash</th></tr></thead><tbody>`;
        for (const e of sample) {
          html += `<tr>
            <td>${esc(e.issued_at || '')}</td>
            <td>${esc(e.action || '')}</td>
            <td>${esc(e.decision || '')}</td>
            <td>${esc(e.kid || '')}</td>
            <td>${esc((e.receipt_hash || '').slice(0, 12))}&hellip;</td>
          </tr>`;
        }
        html += `</tbody></table>`;
        if (evid.length > sample.length) {
          html += `<div class="desc"><small>&hellip; and ${evid.length - sample.length} more in bundle.json</small></div>`;
        }
      }
      html += `</div>`;
    }
  }

  html += `</body></html>`;
  return html;
}

// ───── Helpers ─────

function loadReceipts(dir, warnings) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch (err) {
    throw new Error(`cannot_read_dir:${err.code || err.message}:${dir}`);
  }

  const list = [];
  for (const entry of entries) {
    if (!entry.endsWith('.json')) continue;
    const p = join(dir, entry);
    let st;
    try { st = statSync(p); } catch { continue; }
    if (!st.isFile()) continue;

    let receipt;
    try { receipt = JSON.parse(readFileSync(p, 'utf-8')); }
    catch { warnings.push(`skipped: non-JSON or malformed: ${entry}`); continue; }
    if (!receipt.payload || !receipt.signature) {
      warnings.push(`skipped: missing payload/signature: ${entry}`);
      continue;
    }
    list.push({ ...receipt, __path: p });
  }

  // Sort oldest first for timeline rendering.
  list.sort((a, b) => {
    const aa = (a.payload && a.payload.issued_at) || '';
    const bb = (b.payload && b.payload.issued_at) || '';
    return aa < bb ? -1 : aa > bb ? 1 : 0;
  });
  return list;
}

function filterByWindow(receipts, start, end) {
  if (!start && !end) return receipts;
  return receipts.filter((r) => {
    const t = r.payload && r.payload.issued_at;
    if (!t) return false;
    if (start && t < start) return false;
    if (end && t >= end) return false;
    return true;
  });
}

function matchReceipts(receipts, control) {
  const patterns = control.actions.map((a) => a.toLowerCase());
  const wantWildcard = patterns.includes('*');

  // Collect candidate fields: always action/tool_name/type/decision.
  // This avoids fragile single-field gating; controls describe a
  // semantic category, and any matching evidence surface counts.
  const fields = ['action', 'tool_name', 'type', 'decision'];

  return receipts.filter((r) => {
    if (wantWildcard) return true;
    if (!r.payload) return false;
    for (const f of fields) {
      const v = r.payload[f];
      if (typeof v !== 'string') continue;
      const lv = v.toLowerCase();
      if (patterns.some((p) => lv.includes(p))) return true;
    }
    return false;
  });
}

function summariseReceipt(r) {
  const p = r.payload || {};
  return {
    receipt_hash: '', // filled in by caller if hash is pre-computed
    issued_at: p.issued_at || null,
    action: p.action || p.tool_name || null,
    decision: p.decision || null,
    type: p.type || null,
    issuer_id: p.issuer_id || null,
    agent_id: p.agent_id || null,
    kid: (r.signature && r.signature.kid) || null,
  };
}
