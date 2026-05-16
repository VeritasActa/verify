/**
 * @veritasacta/verify — receipt watcher + webhook dispatcher.
 *
 * Watches a receipt directory in real time. On each new receipt, runs
 * a configurable set of rules and, if any rule fires, POSTs a JSON
 * notification to a webhook URL (Slack, Discord, PagerDuty, Opsgenie,
 * or any generic URL).
 *
 * Designed for operators who want receipts to be an operational
 * signal, not just an audit artifact.
 *
 * @module verify-cli/src/engines/watch
 * @license Apache-2.0
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { watch as fsWatch } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * @typedef {Object} WatchRule
 * @property {string} id
 * @property {'cost_tier_below'|'delegation_expiring_within'|'chain_break'|'deny_decision'|'scrub_triggered'} kind
 * @property {Object} params
 */

/**
 * @typedef {Object} WatchOptions
 * @property {string} receiptsDir
 * @property {string} webhookUrl
 * @property {WatchRule[]} rules
 * @property {'slack'|'discord'|'generic'} [format='generic']
 * @property {(level: 'info'|'warn'|'error', msg: string) => void} [log]
 */

/**
 * Evaluate rules against a single receipt. Returns a list of firing
 * rule results, each with an id, human-readable message, and the
 * triggering receipt digest.
 *
 * @param {Object} receipt
 * @param {WatchRule[]} rules
 * @param {Date} [now]
 * @returns {Array<{rule_id: string, kind: string, message: string}>}
 */
export function evaluateRules(receipt, rules, now = new Date()) {
  const results = [];
  const p = receipt.payload || {};

  for (const rule of rules) {
    switch (rule.kind) {
      case 'cost_tier_below': {
        const threshold = Number(rule.params.threshold);
        const tier = Number(p.cost_tier ?? 0);
        if (tier < threshold) {
          results.push({
            rule_id: rule.id,
            kind: rule.kind,
            message: `cost_tier ${tier} below threshold ${threshold} on ${p.action || p.type}`,
          });
        }
        break;
      }
      case 'delegation_expiring_within': {
        const withinSec = Number(rule.params.within_sec);
        // Check top-level delegation receipts (type=delegation).
        if (p.type === 'delegation' && p.expires_at) {
          const expMs = Date.parse(p.expires_at);
          const dt = (expMs - now.getTime()) / 1000;
          if (Number.isFinite(dt) && dt > 0 && dt < withinSec) {
            results.push({
              rule_id: rule.id,
              kind: rule.kind,
              message: `delegation ${p.delegate_kid || 'unknown'} expires in ${Math.round(dt)}s (threshold ${withinSec}s)`,
            });
          }
        }
        break;
      }
      case 'chain_break': {
        // Presence-only signal — chain break detection is typically
        // upstream of the watcher; this rule fires when a chain
        // explorer has marked this receipt.
        if (p.link_valid === false || p.chain_break === true) {
          results.push({
            rule_id: rule.id,
            kind: rule.kind,
            message: `chain break detected at ${p.action || p.type}`,
          });
        }
        break;
      }
      case 'deny_decision': {
        if (p.decision === 'deny' || p.decision === 'denied') {
          results.push({
            rule_id: rule.id,
            kind: rule.kind,
            message: `deny decision recorded for tool=${p.action || p.tool_name}`,
          });
        }
        break;
      }
      case 'scrub_triggered': {
        if (Array.isArray(p.scrub_detected) && p.scrub_detected.length > 0) {
          results.push({
            rule_id: rule.id,
            kind: rule.kind,
            message: `scrub_secrets redacted ${p.scrub_detected.length} field(s): ${p.scrub_detected.slice(0, 3).join(', ')}`,
          });
        }
        break;
      }
      default:
        // Unknown kind: silently skip. Forward compatibility.
        break;
    }
  }
  return results;
}

/**
 * Format a firing rule as a Slack / Discord / generic JSON payload.
 *
 * @param {{rule_id: string, kind: string, message: string}} fired
 * @param {Object} receipt
 * @param {'slack'|'discord'|'generic'} format
 */
export function formatWebhookPayload(fired, receipt, format = 'generic') {
  const base = {
    rule_id: fired.rule_id,
    kind: fired.kind,
    message: fired.message,
    receipt_kid: (receipt.signature && receipt.signature.kid) || null,
    receipt_action: (receipt.payload && (receipt.payload.action || receipt.payload.tool_name)) || null,
    receipt_issued_at: (receipt.payload && receipt.payload.issued_at) || null,
    occurred_at: new Date().toISOString(),
    source: 'veritasacta/verify:watch',
  };
  if (format === 'slack') {
    return {
      text: `:rotating_light: Veritas Acta alert — ${fired.message}`,
      blocks: [
        {
          type: 'section',
          text: { type: 'mrkdwn', text: `*${fired.rule_id}* fired: ${fired.message}` },
        },
        {
          type: 'context',
          elements: [
            { type: 'mrkdwn', text: `action=\`${base.receipt_action}\` kid=\`${base.receipt_kid}\` at ${base.receipt_issued_at}` },
          ],
        },
      ],
    };
  }
  if (format === 'discord') {
    return {
      content: `🚨 **Veritas Acta alert** — ${fired.rule_id}: ${fired.message}`,
      embeds: [
        {
          title: fired.rule_id,
          description: fired.message,
          fields: [
            { name: 'action', value: base.receipt_action || '(none)', inline: true },
            { name: 'kid', value: base.receipt_kid || '(none)', inline: true },
            { name: 'issued_at', value: base.receipt_issued_at || '(none)', inline: false },
          ],
        },
      ],
    };
  }
  return base;
}

/**
 * Start watching a receipt directory. Returns a stop() function.
 *
 * @param {WatchOptions} opts
 * @returns {Promise<{ stop: () => void, url: string }>}
 */
export async function watchReceipts(opts) {
  const {
    receiptsDir,
    webhookUrl,
    rules = [],
    format = 'generic',
    log = () => {},
  } = opts;

  const dir = resolve(receiptsDir);
  const seen = new Set();

  // Seed with existing receipts so we don't fire on historical data.
  try {
    for (const entry of readdirSync(dir)) {
      if (entry.endsWith('.json')) seen.add(entry);
    }
  } catch (err) {
    throw new Error(`cannot_read_receipts_dir:${err.code || err.message}:${dir}`);
  }

  log('info', `[watch] seeded with ${seen.size} existing receipt(s), watching ${dir}`);

  const watcher = fsWatch(dir, { persistent: true }, async (eventType, filename) => {
    if (!filename || !filename.endsWith('.json')) return;
    if (seen.has(filename)) return;
    seen.add(filename);

    const p = join(dir, filename);
    let st;
    try { st = statSync(p); } catch { return; }
    if (!st.isFile()) return;

    let receipt;
    try { receipt = JSON.parse(readFileSync(p, 'utf-8')); }
    catch (err) {
      log('warn', `[watch] skipped ${filename}: ${err.message}`);
      return;
    }

    const fired = evaluateRules(receipt, rules);
    if (fired.length === 0) return;

    log('info', `[watch] ${filename}: ${fired.length} rule(s) fired`);

    for (const f of fired) {
      const payload = formatWebhookPayload(f, receipt, format);
      try {
        const res = await fetch(webhookUrl, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!res.ok) {
          log('error', `[watch] webhook ${f.rule_id} HTTP ${res.status}`);
        }
      } catch (err) {
        log('error', `[watch] webhook ${f.rule_id} error: ${err.message}`);
      }
    }
  });

  return {
    url: dir,
    stop: () => watcher.close(),
  };
}
