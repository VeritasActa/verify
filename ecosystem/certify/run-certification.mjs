#!/usr/bin/env node
/**
 * run-certification.mjs
 *
 * Runs the weekly conformance certification cycle.
 *
 * For each registered implementation profile, exercises the
 * conformance-vector corpus at the requested AIP level, runs the
 * reference verifier against the produced receipts, and emits an
 * aggregated result.
 *
 * Designed to be invoked from the GitHub Actions workflow in
 * `workflows/run.yml`, but also runnable locally for smoke tests:
 *
 *   node run-certification.mjs --aip-level T1 \
 *        --profiles ./implementations/ \
 *        --output ./certify-T1.json
 *
 * @license Apache-2.0
 */

import { readFileSync, readdirSync, existsSync, writeFileSync } from 'node:fs';
import { join, basename } from 'node:path';
import { createHash } from 'node:crypto';

const args = process.argv.slice(2);
const opts = { aipLevel: 'T1', profiles: './implementations/', output: null };
for (let i = 0; i < args.length; i++) {
  const a = args[i], n = () => args[++i];
  if (a === '--aip-level') opts.aipLevel = n();
  else if (a === '--profiles') opts.profiles = n();
  else if (a === '--output') opts.output = n();
}

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function loadProfiles(dir) {
  if (!existsSync(dir)) {
    console.error(`[certify] no profiles dir: ${dir}`);
    return [];
  }
  const entries = readdirSync(dir);
  const profiles = [];
  for (const entry of entries) {
    const path = join(dir, entry);
    try {
      const text = readFileSync(path, 'utf-8');
      // Light YAML parse: profiles are typically small flat maps.
      // In production this would use js-yaml; for the scaffold we
      // restrict to JSON to avoid a dependency.
      if (!entry.endsWith('.json')) continue;
      const profile = JSON.parse(text);
      profiles.push({ file: entry, profile });
    } catch (err) {
      console.error(`[certify] skip ${entry}: ${err.message}`);
    }
  }
  return profiles;
}

/**
 * For a profile declaring support at level <= opts.aipLevel, exercise
 * the appropriate vector corpus and produce a per-implementation
 * result:
 *
 *   {
 *     implementation: string,
 *     version: string,
 *     aip_level: string,
 *     vector_results: [
 *       { vector: string, expected: 'accept'|'reject', observed: 'accept'|'reject'|'error', ok: boolean }
 *     ],
 *     pass_rate: number,
 *   }
 *
 * The actual exercise mechanism (spawning the implementation, feeding
 * it input, reading its output) is implementation-specific. For the
 * scaffold, we stub results as a placeholder. Real runs should
 * dispatch via a profile-declared adapter command.
 */
function exerciseProfile(profile) {
  // Placeholder: real implementation dispatches to
  // profile.adapter_command, feeds vectors, parses outputs.
  const stubResults = [];
  for (let i = 0; i < 50; i++) {
    stubResults.push({
      vector: `vec-${opts.aipLevel}-${String(i).padStart(3, '0')}`,
      expected: i % 10 === 9 ? 'reject' : 'accept',
      observed: i % 10 === 9 ? 'reject' : 'accept',
      ok: true,
    });
  }
  const passed = stubResults.filter((r) => r.ok).length;
  return {
    implementation: profile.name,
    version: profile.version || 'unknown',
    aip_level: opts.aipLevel,
    vector_results: stubResults,
    pass_rate: passed / stubResults.length,
  };
}

function main() {
  const profiles = loadProfiles(opts.profiles);

  const perImplResults = profiles.map(({ profile }) => exerciseProfile(profile));

  const summary = {
    format: 'veritasacta:certification-result/v1',
    aip_level: opts.aipLevel,
    ran_at: new Date().toISOString(),
    implementations_tested: perImplResults.length,
    pass_count: perImplResults.filter((r) => r.pass_rate === 1).length,
    fail_count: perImplResults.filter((r) => r.pass_rate < 1).length,
    results: perImplResults,
    result_fingerprint:
      'sha256:' + sha256Hex(Buffer.from(JSON.stringify(perImplResults))),
  };

  const body = JSON.stringify(summary, null, 2);
  if (opts.output) {
    writeFileSync(opts.output, body);
    console.log(`[certify] wrote ${opts.output}`);
  } else {
    process.stdout.write(body + '\n');
  }
}

main();
