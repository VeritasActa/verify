#!/usr/bin/env node
/**
 * TRACE's Acta action-receipt fixtures, run through this package's own cli.js.
 *
 * agentrust-io/trace-spec publishes signed Acta receipts beside the result a verifier should give for each check, in
 * examples/action-receipts/acta/expected.json. TRACE's Project Lead asked (agentrust-io/trace-spec#469) that each
 * implementation run such checks from its own repository and publish the results there. This is ours: for every
 * fixture expected.json lists, it runs cli.js from this checkout (never an installed copy) with
 * --jwks <acta-keys.json>, adding --previous <predecessor> where expected.json's `chain` names one, and compares what
 * the CLI decided with expected.json, column by column. Any difference in the verdict or in a check is a failure.
 *
 *   node scripts/trace-fixtures.mjs --trace-spec <checkout> --commit <sha> [--ref <ref>] [--write | --check]
 *
 * TRACE_SPEC_DIR, TRACE_SPEC_COMMIT and TRACE_SPEC_REF may stand in for the options. --write rewrites
 * docs/trace-fixtures.md from the run; --check fails when the committed page differs from it; with neither, the page
 * is printed. The page holds no time, path or version, so the same tree and the same fixtures give the same bytes.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'cli.js');
const PAGE = join(ROOT, 'docs', 'trace-fixtures.md');
const REPOSITORY = 'agentrust-io/trace-spec';
const FIXTURES = 'examples/action-receipts/acta';

// The one table: each expected.json column this CLI decides, the check of its --json result (`checks`) that decides
// it, and the codes that fail that check. A check's result is pass, fail or undecidable; a check an earlier refusal
// left unreached (not_run) is not compared, and any other result decides nothing and differs from pass or fail.
const DECIDED = [
  { column: 'signing_input', check: 'signing_input', codes: ['signature_in_signing_input'], how: 'The signing input carries no `signature` member (draft §6.6).' },
  { column: 'signature', check: 'signature', codes: ['invalid_signature'], how: 'Ed25519 over the JCS signing input, under the key acta-keys.json gives the receipt\'s `kid`.' },
  { column: 'key_window', check: 'key_window', codes: ['key_outside_validity_window'], how: 'The receipt\'s `issued_at` is inside that key\'s `valid_from` / `valid_until` window (§5.5 of the -04 editor\'s copy, VeritasActa/drafts; §9.2 of -03).' },
  { column: 'chain', check: 'previous', codes: ['chain_break', 'malformed_chain_link', 'unsupported_chain_hash_algorithm'], how: 'Run with `--previous <predecessor>`: the receipt\'s `previousReceiptHash` is the §6.7 link of the predecessor expected.json names (§6.7.1 of the -04 editor\'s copy, VeritasActa/drafts).' },
];
const NOT_DECIDED = [
  { column: 'policy_freshness', why: 'It compares `policy_digest` with expected.json\'s `current_policy_digest`. The CLI takes no policy context, so it does not decide whether a policy is still in force.' },
  { column: 'session_binding', why: 'It compares `session_id` with expected.json\'s `expected_session_id`. The CLI takes no session context, so it does not decide which session a receipt belongs to.' },
];
const CODE_COLUMN = Object.fromEntries(DECIDED.flatMap((d) => d.codes.map((code) => [code, d.column])));
const EXIT = { valid: 0, invalid: 1, undecidable: 2 };

function options(argv) {
  const opt = { traceSpec: process.env.TRACE_SPEC_DIR, commit: process.env.TRACE_SPEC_COMMIT, ref: process.env.TRACE_SPEC_REF, mode: 'print' };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--trace-spec') opt.traceSpec = argv[++i];
    else if (a === '--commit') opt.commit = argv[++i];
    else if (a === '--ref') opt.ref = argv[++i];
    else if (a === '--write') opt.mode = 'write';
    else if (a === '--check') opt.mode = 'check';
    else throw new Error(`unexpected argument ${a}`);
  }
  if (!opt.traceSpec) throw new Error('give the trace-spec checkout with --trace-spec <dir> or TRACE_SPEC_DIR');
  return opt;
}

/** The commit the checkout holds: the one given, which must match the checkout's HEAD when the checkout is a git one. */
function commitOf(dir, given) {
  const git = spawnSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  const head = git.status === 0 ? git.stdout.trim() : null;
  if (given && head && given !== head) throw new Error(`the trace-spec checkout is at ${head}, not the ${given} given`);
  const commit = given || head;
  if (!commit || !/^[0-9a-f]{40}$/.test(commit)) throw new Error('give the trace-spec commit (40 hex) with --commit or TRACE_SPEC_COMMIT');
  return commit;
}

/** What the CLI's check says about a column: pass, fail, undecidable, "not reached", or the result that decides nothing. */
function decided(report, check) {
  const c = report.checks?.[check];
  if (!c) return 'not run';
  if (c.result === 'not_run') return 'not reached';
  return c.result;
}

function run(opt) {
  const dir = resolve(opt.traceSpec, FIXTURES);
  const expected = JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf8'));
  const keys = join(dir, expected.key_set || 'acta-keys.json');
  if (!existsSync(keys)) throw new Error(`no key set at ${expected.key_set}`);
  const rows = [];
  const differences = [];
  for (const [fixture, columns] of Object.entries(expected.results)) {
    const previous = expected.chain?.[fixture] ?? null;
    const args = [CLI, join(dir, fixture), '--jwks', keys, '--json', ...(previous ? ['--previous', join(dir, previous)] : [])];
    const p = spawnSync(process.execPath, args, { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', CI: '1' } });
    let report;
    try { report = JSON.parse(p.stdout); } catch { throw new Error(`${fixture}: the CLI gave no JSON (exit ${p.status}): ${p.stderr.trim()}`); }
    const cells = {};
    for (const d of DECIDED) {
      const want = columns[d.column];
      const got = d.check === 'previous' && !previous ? 'n/a' : decided(report, d.check);
      let compared = want !== 'n/a' && got !== 'not reached';
      if (want === 'n/a' && got === 'n/a') compared = false;
      const agrees = !compared || got === want;
      cells[d.column] = { want, got, compared, agrees };
      if (!agrees) differences.push(`${fixture}: ${d.column} is ${want} in expected.json, ${got} from the CLI`);
    }
    // The verdict over the columns this CLI decides, and the failing check, against the CLI's outcome and its code.
    const failing = DECIDED.filter((d) => columns[d.column] === 'fail').map((d) => d.column);
    const verdict = failing.length ? 'invalid' : 'valid';
    if (report.outcome !== verdict) differences.push(`${fixture}: expected.json makes it ${verdict}, the CLI ${report.outcome}`);
    if (p.status !== EXIT[report.outcome]) differences.push(`${fixture}: outcome ${report.outcome} with exit ${p.status}`);
    if (verdict === 'invalid' && !failing.includes(CODE_COLUMN[report.error])) {
      differences.push(`${fixture}: expected.json fails ${failing.join(', ')}, the CLI fails with ${report.error} (${CODE_COLUMN[report.error] ?? 'no column'})`);
    }
    rows.push({ fixture, previous, exit: p.status, outcome: report.outcome, error: report.error ?? null, cells });
  }
  return { expected, rows, differences };
}

function page({ rows, differences }, commit, ref) {
  const compared = rows.reduce((n, r) => n + Object.values(r.cells).filter((c) => c.compared).length, 0);
  const cell = (c) => (c.got === 'n/a' || c.got === 'not reached' ? c.got : !c.compared ? `${c.got} (not compared)` : c.agrees ? c.got : `**${c.got}, expected ${c.want}**`);
  const lines = [
    '# TRACE Acta fixtures',
    '',
    `This package's \`cli.js\` against the Acta action-receipt fixtures that [${REPOSITORY}](https://github.com/${REPOSITORY}) publishes, run by [\`scripts/trace-fixtures.mjs\`](../scripts/trace-fixtures.mjs) and checked on every push by [\`.github/workflows/trace-fixtures.yml\`](../.github/workflows/trace-fixtures.yml), which fails when this page differs from a new run. TRACE's Project Lead asked, on agentrust-io/trace-spec#469, that each implementation run such checks from its own repository and publish the results there.`,
    '',
    `- Repository: [${REPOSITORY}](https://github.com/${REPOSITORY})`,
    `- Commit: [\`${commit}\`](https://github.com/${REPOSITORY}/tree/${commit})${ref ? `, checked out as \`${ref}\`` : ''}`,
    `- Fixtures: \`${FIXTURES}\`, the ${rows.length} that \`expected.json\` lists`,
    '- Run: `node cli.js <fixture> --jwks acta-keys.json --json`, adding `--previous <predecessor>` for each fixture `expected.json` gives a predecessor in `chain`',
    `- Result: ${rows.length} fixtures, ${compared} checks compared, ${differences.length === 0 ? 'no differences' : `${differences.length} difference${differences.length === 1 ? '' : 's'}`}`,
    '',
    '## How each column is decided',
    '',
    'The CLI\'s `--json` result gives each check it made in `checks`, with a result of `pass`, `fail` or `undecidable`. A check that an earlier refusal left unreached (`not_run`) is shown as not reached and not compared: the CLI refuses a receipt whose signing input carries a signature member before checking its signature. Any other result decides nothing, and differs from `pass` or `fail`.',
    '',
    '| `expected.json` column | CLI check | Fails with | What is checked |',
    '| --- | --- | --- | --- |',
    ...DECIDED.map((d) => `| \`${d.column}\` | \`checks.${d.check}\` | ${d.codes.map((c) => `\`${c}\``).join(', ')} | ${d.how} |`),
    '',
    'For each fixture the verdict is invalid when `expected.json` fails any of these columns, and valid otherwise. The CLI\'s `outcome` and exit status must be that verdict, and its `error` must be a code that fails one of the columns `expected.json` fails.',
    '',
    '## Not compared',
    '',
    '| `expected.json` column | Why |',
    '| --- | --- |',
    ...NOT_DECIDED.map((d) => `| \`${d.column}\` | ${d.why} |`),
    '',
    'So fixtures `05` and `06`, which fail only these columns, are valid here, as they should be for a verifier given no policy or session context.',
    '',
    '## Results',
    '',
    `| Fixture | \`--previous\` | Exit | Outcome | Code | ${DECIDED.map((d) => `\`${d.column}\``).join(' | ')} |`,
    `| --- | --- | --- | --- | --- | ${DECIDED.map(() => '---').join(' | ')} |`,
    ...rows.map((r) => `| \`${r.fixture}\` | ${r.previous ? `\`${r.previous}\`` : ''} | ${r.exit} | ${r.outcome} | ${r.error ? `\`${r.error}\`` : ''} | ${DECIDED.map((d) => cell(r.cells[d.column])).join(' | ')} |`),
    '',
  ];
  if (differences.length) lines.push('## Differences', '', ...differences.map((d) => `- ${d}`), '');
  return `${lines.join('\n')}`;
}

const opt = options(process.argv.slice(2));
const commit = commitOf(resolve(opt.traceSpec), opt.commit);
const result = run(opt);
const text = page(result, commit, opt.ref);
if (opt.mode === 'write') writeFileSync(PAGE, text);
else if (opt.mode === 'check') {
  const committed = existsSync(PAGE) ? readFileSync(PAGE, 'utf8') : '';
  if (committed !== text) {
    console.error('docs/trace-fixtures.md differs from this run. Run with --write and commit the page.');
    process.exitCode = 1;
  }
} else process.stdout.write(text);
for (const d of result.differences) console.error(`difference: ${d}`);
console.error(`${result.rows.length} fixtures at ${REPOSITORY}@${commit.slice(0, 12)}: ${result.differences.length} difference${result.differences.length === 1 ? '' : 's'}`);
if (result.differences.length) process.exitCode = 1;
