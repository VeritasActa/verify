#!/usr/bin/env node

/**
 * @veritasacta/verify — unified verifier CLI (v0.5.4)
 *
 * Verifies Ed25519 signed receipts, VOPRF anonymous-credential tokens,
 * Knowledge Unit bundles, and selective-disclosure receipts — all offline,
 * all under one binary with one Sigil commitment.
 *
 * Architecture is modular: this file is the entry point + dispatcher.
 * Cryptographic verification lives in src/engines/*.js. Output formatting
 * lives in src/output/*.js.
 *
 * Usage:
 *   npx @veritasacta/verify receipt.json
 *   npx @veritasacta/verify receipt.json --key <hex>
 *   npx @veritasacta/verify receipt.json --jwks <url>
 *   npx @veritasacta/verify bundle.json --bundle
 *   npx @veritasacta/verify ku.json --mode ku
 *   npx @veritasacta/verify receipt.json --disclose field1,field2:salt:value
 *   npx @veritasacta/verify receipt.json --require-context sensor:temp<18
 *   npx @veritasacta/verify --self-check
 *   npx @veritasacta/verify --self-test
 *   npx @veritasacta/verify --capabilities
 *
 * Exit codes:
 *   0 = signature valid (proven authentic)
 *   1 = signature invalid (proven tampered)
 *   2 = verifier error (malformed input, missing key, unsupported algorithm)
 *
 * References:
 *   - draft-farley-acta-signed-receipts-03
 *   - draft-farley-acta-knowledge-units-00
 *   - AIP-0001, AIP-0002, AIP-0003
 *   - Provisional patents #1-5
 *
 * @license Apache-2.0
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { detectFormat } from './src/detect.js';
import { verifyReceipt, verifyBundle } from './src/engines/ed25519-receipt.js';
import { verifyVoprfToken } from './src/engines/voprf-token.js';
import { verifyKnowledgeUnit } from './src/engines/knowledge-unit.js';
import {
  verifySelectiveDisclosure,
  listRedactedFields,
} from './src/engines/selective-disclosure.js';
import {
  verifyCommittedReceipt,
  loadDisclosuresFromText,
} from './src/engines/commitment-mode.js';
import { selfCheck, evaluateLiveContext } from './src/engines/sigil.js';
import {
  buildCanonicalAttestation,
  buildVerificationReceipt,
} from './src/engines/attestation.js';
import { replayChain } from './src/engines/bulk.js';
import { diffReceipts } from './src/engines/diff.js';
import { runInit, buildNextSteps } from './src/engines/init.js';
import { runProxy } from './src/engines/proxy.js';
import { runDaemon } from './src/engines/daemon.js';
import { verifyPrompt } from './src/engines/prompt.js';
import { exploreChain, renderChainTree } from './src/engines/chain-explore.js';
import { exportCompliance, renderComplianceHTML } from './src/engines/compliance-export.js';
import { startDashboard } from './src/engines/dashboard.js';
import { verifyDelegationChain } from './src/engines/delegation.js';
import { verifyCosignatures } from './src/engines/cosign.js';
import { parseContextArgs } from './src/context/live-context.js';
import { detectTier } from './src/conformance.js';
import { resolveFromJwks } from './src/util/jwks.js';
import { appendAuditEntry } from './src/util/audit-log.js';
import { fipsStatus } from './src/util/fips.js';
import { renderHtmlReport } from './src/output/html-report.js';
import { getError, exitCodeFor } from './src/errors.js';

import {
  formatReceiptResult,
  formatBundleResult,
  formatKuResult,
  formatSelfCheckResult,
  green,
  red,
  yellow,
  dim,
  bold,
  teal,
  renderTerminalSigil,
} from './src/output/terminal.js';
import { formatAsJson } from './src/output/json.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(__dirname, 'package.json'), 'utf-8'));

const MODE_LABELS = {
  'ed25519-receipt-v1': 'Ed25519 receipt v1 (RFC 8032)',
  'ed25519-receipt-v2': 'Ed25519 receipt v2 (RFC 8032 + draft-farley-acta-signed-receipts)',
  'ed25519-passport': 'Ed25519 Passport envelope (RFC 8032)',
  'ed25519-bundle': 'Ed25519 audit bundle',
  'voprf-token': 'VOPRF token (RFC 9497)',
  'knowledge-unit': 'Knowledge Unit bundle (draft-farley-acta-knowledge-units)',
};

// ──────────────────────────────────────────────────────────────────
// CLI argument parsing
// ──────────────────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    file: null,
    publicKey: null,
    jwksUrl: null,
    trustAnchor: null,
    stdin: false,
    mode: 'auto',
    bundle: false,
    json: false,
    help: false,
    version: false,
    verbose: false,
    selfTest: false,
    selfCheck: false,
    capabilities: false,
    allowEmbeddedKey: false,
    requireContext: [],
    disclose: [],
    disclosureFile: null,
    tier: null,
    strict: false,
    noSigil: false,
    attest: false,
    attestOrg: null,
    attestKey: null,
    pinSigil: null,
    auditLog: null,
    replayChain: null,
    diff: null,
    auditReport: false,
    output: null,
    emitVerificationReceipt: false,
    fips: false,
    subcommand: null,
    force: false,
    proxyTarget: null,
    proxyReceiptsDir: null,
    daemonSocket: null,
    frameworkOverride: null,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = () => args[++i];
    switch (arg) {
      case '--help':
      case '-h': opts.help = true; break;
      case '--version':
      case '-V': opts.version = true; break;
      case '--key':
      case '-k': opts.publicKey = next(); break;
      case '--jwks': opts.jwksUrl = next(); break;
      case '--trust-anchor': opts.trustAnchor = next(); break;
      case '--stdin': opts.stdin = true; break;
      case '--mode': opts.mode = next(); break;
      case '--bundle': opts.bundle = true; break;
      case '--json': opts.json = true; break;
      case '--verbose':
      case '-v': opts.verbose = true; break;
      case '--self-test': opts.selfTest = true; break;
      case '--self-check': opts.selfCheck = true; break;
      case '--capabilities': opts.capabilities = true; break;
      case '--allow-embedded-key': opts.allowEmbeddedKey = true; break;
      case '--require-context': opts.requireContext.push(next()); break;
      case '--disclose': opts.disclose.push(next()); break;
      case '--disclosure-file': opts.disclosureFile = next(); break;
      case '--tier': opts.tier = Number(next()); break;
      case '--strict': opts.strict = true; break;
      case '--no-sigil': opts.noSigil = true; break;
      case '--attest': opts.attest = true; break;
      case '--attest-org': opts.attestOrg = next(); break;
      case '--attest-key': opts.attestKey = next(); break;
      case '--pin-sigil': opts.pinSigil = next(); break;
      case '--audit-log': opts.auditLog = next(); break;
      case '--replay-chain': opts.replayChain = next(); break;
      case '--diff': opts.diff = next(); break;
      case '--audit-report': opts.auditReport = true; break;
      case '--output': opts.output = next(); break;
      case '--emit-verification-receipt': opts.emitVerificationReceipt = true; break;
      case '--fips': opts.fips = true; break;
      case '--allow-partial-voprf': opts.allowPartialVoprf = true; break;
      case '--force': opts.force = true; break;
      case '--target': opts.proxyTarget = next(); break;
      case '--framework': opts.frameworkOverride = next(); break;
      case '--receipts-dir': opts.proxyReceiptsDir = next(); break;
      case '--socket': opts.daemonSocket = next(); break;
      case '--prompt-receipt': opts.promptReceipt = next(); break;
      case '--sigstore-bundle': opts.sigstoreBundle = next(); break;
      case '--expected-hash': opts.expectedHash = next(); break;
      case '--search-dir': opts.chainSearchDir = next(); break;
      case '--max-depth': opts.chainMaxDepth = Number(next()); break;
      case '--profile': opts.profile = next(); break;
      case '--start-date': opts.startDate = next(); break;
      case '--end-date': opts.endDate = next(); break;
      case '--org': opts.organization = next(); break;
      case '--port': opts.dashboardPort = Number(next()); break;
      case '--bind': opts.dashboardBind = next(); break;
      case '--bilateral': opts.proxyBilateral = true; break;
      case '--server-key': opts.serverKey = next(); break;
      case '--scrub-secrets': opts.scrubSecrets = true; break;
      case '--trace-id': opts.traceId = next(); break;
      case '--group-by-trace': opts.groupByTrace = true; break;
      case 'init':
      case 'proxy':
      case 'daemon':
      case 'prompt':
      case 'chain':
      case 'compliance':
      case 'dashboard':
        if (!opts.subcommand) opts.subcommand = arg;
        else if (!arg.startsWith('-')) opts.file = arg;
        break;
      case 'explore':
        // `verify chain explore <file>` → subcommand stays "chain",
        // sub-subcommand captured below
        if (opts.subcommand === 'chain') opts.chainVerb = arg;
        else if (!arg.startsWith('-')) opts.file = arg;
        break;
      default:
        if (!arg.startsWith('-')) opts.file = arg;
        // unknown flags silently ignored (forward-compat)
    }
  }
  return opts;
}

function printHelp() {
  console.log(`
${bold('@veritasacta/verify')} ${PKG.version} — unified verifier for signed receipts, VOPRF tokens, and Knowledge Units

${bold('Usage:')}
  npx @veritasacta/verify <file.json>                        Auto-detect format, verify
  npx @veritasacta/verify <file.json> --key <hex>            Provide verification key
  npx @veritasacta/verify <file.json> --jwks <url>           Fetch key from JWKS
  npx @veritasacta/verify <file.json> --mode receipt|voprf|ku
  npx @veritasacta/verify <bundle.json> --bundle             Verify audit bundle
  cat receipt.json | npx @veritasacta/verify --stdin         Read from stdin
  npx @veritasacta/verify <file.json> --json                 Machine-readable output

${bold('Selective disclosure (AIP-0002 legacy):')}
  --disclose field:salt:value                               Reveal a field and verify its commitment

${bold('Commitment-mode disclosure (draft-farley-acta-signed-receipts-01):')}
  --disclosure-file <path.json>                             Verify Merkle inclusion proofs against committed_fields_root

${bold('Live-context verification (Sigil claim 2):')}
  --require-context clock:±5s
  --require-context geofence:inside:<polygon>
  --require-context sensor:temp<18

${bold('Subcommands:')}
  init                      Zero-config onboarding wizard (detects framework, generates keys)
  proxy --target "<cmd>"    Wrap an MCP server; sign every tools/call transparently
  daemon                    Sidecar daemon: sign receipts over a unix socket (any language)
  prompt <path>             Verify a prompt/skill/system-instruction file's provenance
                              [--prompt-receipt <r.json> | --sigstore-bundle <b.json> | --expected-hash <hex>]
  chain explore <r.json>    Walk a receipt chain to its root; verify every hash link
                              [--search-dir <dir>] [--max-depth N] [--json]
  compliance                SOC 2 / ISO 42001 / EU AI Act evidence bundle from a receipt directory
                              --receipts-dir <dir> [--framework soc2|iso42001|eu-ai-act|all]
                              [--start-date ISO] [--end-date ISO] [--org "<name>"] [--output audit.html|bundle.json]
  dashboard                 Start local audit dashboard server (loopback only, no telemetry)
                              [--port 3847] [--bind 127.0.0.1] [--receipts-dir <dir>]
  proxy --target "<cmd>"    Already-present wrap-and-sign proxy. New flags:
                              [--bilateral --server-key <file>]  Cosign every receipt with a second key
                              [--scrub-secrets]  Redact api_key/token/etc in outgoing args and flag on receipt
                              [--trace-id <id>]  Stamp a workflow trace_id on every receipt

${bold('Options:')}
  --key, -k <hex>          Ed25519 public key (64 hex chars)
  --jwks <url>             JWKS endpoint to fetch signing key
  --trust-anchor <file>    Local trust-anchor JSON with public keys
  --mode <m>               Force mode: receipt|voprf|ku|auto (default: auto)
  --bundle                 Verify as audit bundle
  --stdin                  Read input from stdin
  --json                   Output JSON
  --verbose, -v            Detailed verification info
  --tier N                 Require minimum conformance tier (1-5)
  --pin-sigil <hex>        Require installed Sigil fingerprint to match
  --strict                 Disable all deprecated fallbacks
  --fips                   Enforce FIPS-approved algorithms only
  --audit-log <file>       Append verification event to a local JSONL audit log
  --self-test              Verify bundled sample artifacts
  --self-check             Prove this verifier is the canonical release
  --capabilities           List supported modes/algorithms/tiers
  --allow-embedded-key     DEPRECATED. Accept keys embedded in payloads.
                           Removed in v0.6.0.
  --allow-partial-voprf    Treat a partial (structural-only) VOPRF result
                           as valid. Default fails closed (exit 2).
                           Full DLEQ verification lands in v0.6.0.
  --no-sigil               Suppress Sigil art in terminal output
  --help, -h
  --version, -V

${bold('Bulk / replay / diff:')}
  --replay-chain <file>    Verify every receipt in a JSONL chain file
  --diff <other-file>      Show structural diff between two receipts

${bold('Attestation and audit:')}
  --attest                 Emit a canonical verifier attestation (signed)
  --attest-org <name>      Include this org name in the attestation
  --attest-key <file>      Override attester key location
                           (default: ~/.veritasacta-verify/attester.json)
  --emit-verification-receipt
                           Emit a signed verification receipt for the subject
  --audit-report           Render an HTML audit report
  --output <file>          Write output to a file (HTML reports, attestations)

${bold('Supported formats:')}
  v1 artifacts, v2 artifacts, Passport envelopes, audit bundles,
  VOPRF tokens, Knowledge Unit bundles, selective-disclosure receipts.

${bold('Exit codes:')}
  0  Valid — proven authentic
  1  Invalid — proven tampered
  2  Undecidable — malformed input, missing key, unsupported algorithm,
                   or --tier requirement not achieved

${bold('Standards:')}
  RFC 8032 (Ed25519), RFC 8785 (JCS), RFC 9497 (VOPRF),
  RFC 7517/7638 (JWK / thumbprint),
  draft-farley-acta-signed-receipts-03,
  draft-farley-acta-knowledge-units-00,
  AIP-0001, AIP-0002, AIP-0003.

${bold('Protocol:')}  https://veritasacta.com (open, Apache-2.0)
${bold('Managed:')}   https://scopeblind.com (optional, commercial)
`);
}

function printCapabilities() {
  console.log(JSON.stringify({
    package: PKG.name,
    version: PKG.version,
    modes: Object.keys(MODE_LABELS),
    algorithms: ['ed25519', 'EdDSA', 'voprf-p256-sha256'],
    unsupported_but_recognized: ['ed25519+ml-dsa-65', 'ed25519+dilithium3'],
    tiers: [1, 2, 3, 4],
    max_tier_v0_5_0: 4,
    features: [
      'ed25519-receipt-verification',
      'voprf-token-structural-verification',
      'knowledge-unit-bundle-verification',
      'selective-disclosure-aip-0002',
      'sigil-self-check-claim-1',
      'sigil-live-context-claim-2',
      'conformance-tier-detection',
      'embedded-key-rejection',
    ],
    specs: [
      'RFC 8032', 'RFC 8785', 'RFC 9497', 'RFC 7517', 'RFC 7638',
      'draft-farley-acta-signed-receipts-03',
      'draft-farley-acta-knowledge-units-00',
      'AIP-0001', 'AIP-0002', 'AIP-0003',
    ],
    wayfinding: {
      protocol: 'https://veritasacta.com',
      managed: 'https://scopeblind.com',
    },
  }, null, 2));
}

// ──────────────────────────────────────────────────────────────────
// Self-check: prove this binary is the canonical unmodified release
// ──────────────────────────────────────────────────────────────────

async function runSelfCheck() {
  const sigilPath = join(__dirname, 'sigil.json');
  let sigil;
  try {
    sigil = JSON.parse(readFileSync(sigilPath, 'utf-8'));
  } catch {
    console.log(`\n  ${red('✗')} No sigil.json found — this verifier has no Sigil commitment.`);
    console.log(`    This may be a development build or a fork.\n`);
    process.exit(2);
  }

  // Use the shared monitored file list (keeps runSelfCheck and
  // selfCheckResult in sync).
  const bufs = [];
  for (const f of MONITORED_FILES_FOR_SIGIL) {
    try { bufs.push(readFileSync(join(__dirname, f))); } catch { /* missing */ }
  }
  const installedSourceBytes = Buffer.concat(bufs);

  const r = selfCheck({ sigil, installedSourceBytes });
  r.projectPublicKey = sigil.project_public_key;
  console.log(bold('@veritasacta/verify — self-check'));
  console.log(formatSelfCheckResult(r));
  process.exit(r.canonical ? 0 : 1);
}

// ──────────────────────────────────────────────────────────────────
// Self-test: verify bundled samples
// ──────────────────────────────────────────────────────────────────

async function runSelfTest(opts) {
  const samplesDir = join(__dirname, 'samples');
  const testKey = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
  let allPassed = true;

  console.log(`\n${bold('@veritasacta/verify — self-test')}\n`);
  if (!process.env.CI && !process.env.NO_COLOR) {
    console.log(renderTerminalSigil(testKey));
    console.log('');
  }

  try {
    const receipt = JSON.parse(readFileSync(join(samplesDir, 'sample-receipt.json'), 'utf-8'));
    const detected = detectFormat(receipt);
    const r = await verifyReceipt(receipt, detected.mode, { publicKey: testKey });
    if (r.valid) {
      console.log(`  ${green('✓')} Sample receipt: ${green('VALID')}  (${r.type}, kid: ${r.kid || 'n/a'})`);
    } else {
      console.log(`  ${red('✗')} Sample receipt: ${red('INVALID')}  (${r.error})`);
      allPassed = false;
    }
  } catch (e) {
    console.log(`  ${red('✗')} Sample receipt: ${red(e.message)}`);
    allPassed = false;
  }

  try {
    const bundle = JSON.parse(readFileSync(join(samplesDir, 'sample-bundle.json'), 'utf-8'));
    const r = await verifyBundle(bundle, { publicKey: testKey });
    if (r.valid) {
      console.log(`  ${green('✓')} Sample bundle:  ${green('VALID')}  (${r.passed}/${r.total} receipts)`);
    } else {
      console.log(`  ${red('✗')} Sample bundle:  ${red('INVALID')}  (${r.failed} failed)`);
      allPassed = false;
    }
  } catch (e) {
    console.log(`  ${red('✗')} Sample bundle: ${red(e.message)}`);
    allPassed = false;
  }

  console.log('');
  if (allPassed) {
    console.log(`  ${green('All self-tests passed.')} The verifier is working correctly.`);
    console.log(`  ${dim('No ScopeBlind servers were contacted. No accounts required.')}`);
  } else {
    console.log(`  ${red('Some self-tests failed.')} Check the output above.`);
  }
  console.log('');
  process.exit(allPassed ? 0 : 1);
}

// ──────────────────────────────────────────────────────────────────
// Dispatch
// ──────────────────────────────────────────────────────────────────

async function readInput(opts) {
  if (opts.stdin) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf-8');
  }
  if (opts.file) return readFileSync(opts.file, 'utf-8');
  return null;
}

async function dispatch(input, opts) {
  // Forced-mode overrides
  let detected = detectFormat(input);
  if (opts.mode && opts.mode !== 'auto') {
    const forced = opts.mode.toLowerCase();
    if (forced === 'receipt') detected.mode = 'ed25519-passport';
    else if (forced === 'voprf') detected.mode = 'voprf-token';
    else if (forced === 'ku') detected.mode = 'knowledge-unit';
    else if (forced === 'bundle') detected.mode = 'ed25519-bundle';
  }
  if (opts.bundle) detected.mode = 'ed25519-bundle';

  // Resolve JWKS if needed
  let publicKey = opts.publicKey;
  let keySource = publicKey ? 'provided' : null;
  if (!publicKey && opts.jwksUrl) {
    const kid = input.kid || input.signature?.kid;
    const resolved = await resolveFromJwks(opts.jwksUrl, kid);
    if (resolved.key) {
      publicKey = resolved.key;
      keySource = resolved.source?.resolved ? `jwks:${resolved.source.resolved}` : 'jwks';
    } else {
      const result = {
        valid: false,
        error: 'jwks_fetch_failed',
        format: detected.mode,
        detail: resolved.error,
      };
      return result;
    }
  }

  const subOpts = { ...opts, publicKey };

  // Route to engine
  switch (detected.mode) {
    case 'ed25519-bundle': {
      return await verifyBundle(input, subOpts);
    }
    case 'knowledge-unit': {
      const r = await verifyKnowledgeUnit(input, subOpts);
      const tier = detectTier({ mode: 'knowledge-unit', payloadFields: {} });
      return { ...r, tier };
    }
    case 'voprf-token': {
      const r = await verifyVoprfToken(input, subOpts);
      const tier = detectTier({
        mode: 'voprf-token',
        payloadFields: {
          transport_hint: r.transport_hint,
        },
        voprfVerified: r.valid,
      });
      return { ...r, tier, modeLabel: MODE_LABELS['voprf-token'] };
    }
    case 'ed25519-receipt-v1':
    case 'ed25519-receipt-v2':
    case 'ed25519-passport': {
      const r = await verifyReceipt(input, detected.mode, subOpts);

      // Selective disclosure: attach if commitments present.
      // Two formats supported:
      //   - Legacy AIP-0002 (_commitments map + --disclose field:salt:value)
      //   - draft-farley-acta-signed-receipts-01 commitment-mode
      //     (committed_fields_root + --disclosure-file path)
      let disclosureResult = null;
      const hasCommittedFieldsRoot = detected.signals?.includes('committed_fields_root');
      const hasLegacyCommitments = detected.signals?.includes('_commitments');

      if (hasCommittedFieldsRoot) {
        // draft-01 commitment-mode path
        let disclosures = [];
        if (opts.disclosureFile) {
          try {
            const fs = await import('node:fs');
            const text = fs.readFileSync(opts.disclosureFile, 'utf8');
            disclosures = loadDisclosuresFromText(text);
          } catch (err) {
            r.valid = false;
            r.error = `disclosure_file_load_failed: ${err?.message ?? 'unknown'}`;
          }
        }
        if (r.valid !== false) {
          disclosureResult = verifyCommittedReceipt(input, disclosures);
          r.committedFieldsRoot = input.committed_fields_root;
          r.committedFieldNames = input.committed_field_names;
          r.disclosedFields = disclosures.map((d) => d.name);
          if (!disclosureResult.valid) {
            r.valid = false;
            r.error = disclosureResult.error || 'commitment_mismatch';
          }
        }
      } else if (hasLegacyCommitments) {
        // Legacy AIP-0002 path
        const disclosures = parseDisclosures(opts.disclose);
        disclosureResult = verifySelectiveDisclosure(input, disclosures);
        r.redactedFields = listRedactedFields(input);
        r.disclosedFields = disclosures.map((d) => d.field);
        if (!disclosureResult.valid) {
          r.valid = false;
          r.error = 'commitment_mismatch';
        }
      }

      // Live-context predicates
      if (opts.requireContext.length > 0) {
        const preds = parseContextArgs(opts.requireContext);
        const ctx = await evaluateLiveContext(preds);
        r.contextChecks = ctx.checks;
        if (!ctx.allSatisfied) {
          r.valid = false;
          r.error = r.error || 'context_requirement_unmet';
        }
      }

      // Surface attestation_mode as dedicated output field
      if (r.payloadFields?.attestation_mode) {
        r.attestationMode = r.payloadFields.attestation_mode;
      }
      if (r.payloadFields?.scope) r.scope = r.payloadFields.scope;
      if (r.payloadFields?.nullifier) r.nullifier = r.payloadFields.nullifier;
      if (r.payloadFields?.transport_hint) r.transport_hint = r.payloadFields.transport_hint;

      const tier = detectTier({
        mode: detected.mode,
        payloadFields: r.payloadFields,
        disclosuresVerified: disclosureResult?.disclosuresVerified || 0,
      });
      r.tier = tier;
      r.modeLabel = MODE_LABELS[detected.mode];
      r.specVersion = 'draft-farley-acta-signed-receipts-03';
      return r;
    }
    default:
      return {
        valid: false,
        error: 'unknown_format',
        format: 'unknown',
        detail: `Could not detect format. Signals: ${detected.signals.join(', ') || 'none'}`,
      };
  }
}

/**
 * Parse --disclose arguments into disclosure packages.
 * Format: "field.path:salt_hex:json_value" (value is JSON-parsed)
 */
function parseDisclosures(args) {
  const packages = [];
  for (const a of args) {
    const firstColon = a.indexOf(':');
    const secondColon = a.indexOf(':', firstColon + 1);
    if (firstColon < 0 || secondColon < 0) continue;
    const field = a.slice(0, firstColon);
    const salt = a.slice(firstColon + 1, secondColon);
    const raw = a.slice(secondColon + 1);
    let value;
    try { value = JSON.parse(raw); } catch { value = raw; }
    packages.push({ field, salt, value });
  }
  return packages;
}

// ──────────────────────────────────────────────────────────────────
// Main
// ──────────────────────────────────────────────────────────────────

function applyTierGate(result, minTier) {
  if (!minTier) return result;
  const achieved = result.tier?.tier || 1;
  if (achieved < minTier) {
    return {
      ...result,
      valid: false,
      error: 'tier_not_achieved',
      detail: `Required tier T${minTier}, achieved T${achieved}`,
    };
  }
  return result;
}

/**
 * Load and parse the Sigil commitment from disk.
 * Used by attestation and report generators.
 */
function loadSigil() {
  try {
    return JSON.parse(readFileSync(join(__dirname, 'sigil.json'), 'utf-8'));
  } catch {
    return null;
  }
}

/**
 * --pin-sigil: require the installed Sigil fingerprint to match a
 * specified value. Fails early if mismatch.
 */
function enforcePinSigil(expected) {
  const sigil = loadSigil();
  if (!sigil) {
    console.error(red('--pin-sigil requires a sigil.json; none found.'));
    process.exit(2);
  }
  if (sigil.fingerprint !== expected) {
    console.error(red(`--pin-sigil: mismatch (expected ${expected}, got ${sigil.fingerprint})`));
    console.error(yellow(`Installed verifier is "${sigil.name}" (${sigil.fingerprint}); expected fingerprint ${expected}.`));
    console.error(dim(`Ensure you have installed the expected release: npm install @veritasacta/verify@<version>`));
    process.exit(2);
  }
}

/**
 * --replay-chain FILE: verify an entire JSONL chain.
 */
async function runReplayChain(opts) {
  const sigil = loadSigil();
  const result = await replayChain(opts.replayChain, opts);

  if (opts.auditReport) {
    let attestation = null;
    if (opts.attest) {
      const r = selfCheckResult(sigil);
      attestation = buildCanonicalAttestation({
        sigil, canonical: r.canonical, org: opts.attestOrg, keyPath: opts.attestKey,
      });
    }
    const html = renderHtmlReport({ result, sigil, attestation, title: 'Veritas Acta chain-replay audit report' });
    if (opts.output) {
      writeFileSync(opts.output, html);
      console.log(dim(`wrote ${opts.output}`));
    } else {
      console.log(html);
    }
    process.exit(result.valid ? 0 : 1);
  }

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`\n${bold('Chain replay result')}`);
    console.log(`  Total:       ${result.total}`);
    console.log(`  Verified:    ${green(String(result.verified))}`);
    console.log(`  Failed:      ${result.failed > 0 ? red(String(result.failed)) : '0'}`);
    console.log(`  Chain breaks: ${result.chainBreaks > 0 ? red(String(result.chainBreaks)) : '0'}`);
    if (result.errors.length > 0) {
      console.log(`\n  ${red('Errors:')}`);
      for (const e of result.errors.slice(0, 20)) console.log(`    ${red('•')} ${e}`);
      if (result.errors.length > 20) console.log(`    ${dim(`... ${result.errors.length - 20} more`)}`);
    }
    console.log('');
  }
  process.exit(result.valid ? 0 : 1);
}

/**
 * --diff A B: show structural differences between two receipts.
 */
async function runDiff(opts) {
  const a = JSON.parse(await readInput(opts) || '{}');
  const b = JSON.parse(readFileSync(opts.diff, 'utf-8'));
  const d = diffReceipts(a, b);
  if (opts.json) {
    console.log(JSON.stringify(d, null, 2));
  } else {
    console.log(`\n${bold('Receipt diff')}`);
    console.log(`  Canonical hash A: ${dim(d.canonical_hash_a)}`);
    console.log(`  Canonical hash B: ${dim(d.canonical_hash_b)}`);
    console.log(`  Payload identical: ${d.hash_equal ? green('yes') : red('no')}`);
    console.log(`  Signature identical: ${d.signature_equal ? green('yes') : red('no')}`);
    if (d.added.length > 0) console.log(`\n  ${green('Added:')}     ${d.added.join(', ')}`);
    if (d.removed.length > 0) console.log(`  ${red('Removed:')}   ${d.removed.join(', ')}`);
    if (d.changed.length > 0) {
      console.log(`  ${yellow('Changed:')}`);
      for (const c of d.changed) {
        console.log(`    ${c.field}: ${dim(JSON.stringify(c.before))} -> ${dim(JSON.stringify(c.after))}`);
      }
    }
    console.log('');
  }
  process.exit(d.hash_equal && d.signature_equal ? 0 : 1);
}

/**
 * verify prompt <file> [--prompt-receipt <r> | --sigstore-bundle <b> | --expected-hash <h>]
 *
 * Verify the provenance of a prompt / instruction file against one of
 * three sources. Closes the CLAUDE.md / SKILLS.md supply-chain gap.
 */
async function runPromptVerify(opts) {
  if (!opts.file) {
    console.error(red('  verify prompt requires a file path to the prompt'));
    console.error(dim('  usage: verify prompt <path> [--prompt-receipt <receipt.json> | --sigstore-bundle <bundle.json> | --expected-hash <hex>]'));
    process.exit(2);
  }
  const result = await verifyPrompt({
    promptPath: opts.file,
    receiptPath: opts.promptReceipt,
    sigstoreBundle: opts.sigstoreBundle,
    expectedHash: opts.expectedHash,
  });

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log('');
    console.log(`${bold('Prompt verification')}`);
    console.log(`  File:      ${result.prompt_path}`);
    console.log(`  Hash:      ${dim(result.prompt_hash)}`);
    if (result.source) console.log(`  Source:    ${result.source}`);
    if (result.expected_hash) {
      const eq = result.expected_hash === result.prompt_hash;
      console.log(`  Expected:  ${dim(result.expected_hash)} ${eq ? green('match') : red('MISMATCH')}`);
    }
    if (result.receipt_summary) {
      console.log(`  Receipt:   ${dim(JSON.stringify(result.receipt_summary))}`);
    }
    if (result.bundle_summary) {
      console.log(`  Bundle:    ${dim(JSON.stringify(result.bundle_summary))}`);
    }
    if (result.valid) {
      console.log(`  ${green('\u2713')} prompt matches the asserted provenance`);
    } else {
      console.log(`  ${red('\u2717')} ${result.error || 'verification failed'}`);
    }
    console.log('');
  }
  process.exit(result.valid ? 0 : 1);
}

/**
 * verify chain explore <file> [--search-dir <dir>] [--max-depth N]
 *
 * Walk the causal ancestry of a receipt via previousReceiptHash and
 * validate every hash link along the way. Surfaces cryptographic
 * causal integrity as a concrete operation.
 */
async function runChainExplore(opts) {
  if (opts.chainVerb !== 'explore') {
    console.error(red(`  unknown chain subcommand: ${opts.chainVerb || '(none)'}`));
    console.error(dim('  usage: verify chain explore <receipt.json> [--search-dir <dir>] [--max-depth N]'));
    process.exit(2);
  }
  if (!opts.file) {
    console.error(red('  verify chain explore requires a receipt file path'));
    process.exit(2);
  }
  const result = await exploreChain({
    receiptPath: opts.file,
    searchDir: opts.chainSearchDir,
    maxDepth: opts.chainMaxDepth,
  });

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(renderChainTree(result));
  }
  process.exit(result.valid ? 0 : 1);
}

/**
 * verify compliance [--framework soc2|iso42001|eu-ai-act|all]
 *                   --receipts-dir <dir> [--start-date ISO] [--end-date ISO]
 *                   [--org "<name>"] [--output <file>] [--json]
 *
 * Produce a compliance evidence bundle: control-mapped receipt
 * summaries, HTML audit report suitable for auditors.
 */
async function runCompliance(opts) {
  const dir = opts.proxyReceiptsDir || opts.receiptsDir || opts.file;
  if (!dir) {
    console.error(red('  verify compliance requires --receipts-dir <dir>'));
    console.error(dim('  usage: verify compliance --receipts-dir <dir> [--framework soc2|iso42001|eu-ai-act|all]'));
    console.error(dim('                            [--start-date ISO] [--end-date ISO] [--org "<name>"] [--output <file>] [--json]'));
    process.exit(2);
  }
  let result;
  try {
    result = exportCompliance({
      receiptsDir: dir,
      framework: opts.frameworkOverride || 'all',
      startDate: opts.startDate,
      endDate: opts.endDate,
      organizationName: opts.organization,
    });
  } catch (err) {
    console.error(red(`  compliance export failed: ${err.message}`));
    process.exit(2);
  }

  if (opts.output) {
    const isHtml = opts.output.endsWith('.html');
    const body = isHtml
      ? renderComplianceHTML(result)
      : JSON.stringify(result, null, 2);
    writeFileSync(opts.output, body);
    console.log(green(`  ✓ Compliance bundle written to ${opts.output}`));
    console.log(dim(`  Receipts scanned: ${result.manifest.receipts_scanned} / in window: ${result.manifest.receipts_in_window}`));
    for (const [fwId, fw] of Object.entries(result.manifest.frameworks)) {
      const evidenced = Object.values(fw.controls).filter((c) => c.evidence_count > 0).length;
      const total = Object.keys(fw.controls).length;
      console.log(dim(`  ${fw.framework}: ${evidenced}/${total} controls evidenced`));
    }
    return;
  }

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  // Terminal rendering
  console.log('');
  console.log(bold('Compliance evidence bundle'));
  console.log(`  Organization: ${result.manifest.organization}`);
  console.log(`  Receipts:     ${result.manifest.receipts_scanned} scanned, ${result.manifest.receipts_in_window} in window`);
  if (result.manifest.window.start || result.manifest.window.end) {
    console.log(`  Window:       ${result.manifest.window.start || '(begin)'} → ${result.manifest.window.end || '(end)'}`);
  }
  for (const [, fw] of Object.entries(result.manifest.frameworks)) {
    console.log('');
    console.log(bold(`  ${fw.framework}`));
    for (const [ctrlId, ctrl] of Object.entries(fw.controls)) {
      const mark = ctrl.evidence_count > 0 ? green('●') : dim('○');
      console.log(`    ${mark} ${ctrlId}  ${ctrl.name}  ${dim(`(${ctrl.evidence_count})`)}`);
    }
  }
  if (result.warnings.length) {
    console.log('');
    console.log(yellow('  Warnings:'));
    for (const w of result.warnings) console.log(`    • ${w}`);
  }
  console.log('');
}

/**
 * verify dashboard [--port 3847] [--bind 127.0.0.1] [--receipts-dir <dir>]
 *
 * Spin up the local dashboard server. Opens a browser tab to it.
 * Binds loopback only.
 */
async function runDashboard(opts) {
  const receiptsDir = opts.proxyReceiptsDir || opts.receiptsDir;
  let dash;
  try {
    dash = await startDashboard({
      port: opts.dashboardPort || 3847,
      bind: opts.dashboardBind || '127.0.0.1',
      receiptsDir,
    });
  } catch (err) {
    console.error(red(`  dashboard failed to start: ${err.message}`));
    process.exit(2);
  }
  console.log('');
  console.log(bold('  Veritas Acta dashboard'));
  console.log(`  Serving at: ${dash.url}`);
  if (receiptsDir) {
    console.log(`  Receipts:   ${receiptsDir}`);
  } else {
    console.log(dim(`  Receipts:   (none — paste JSON or drop files in the UI)`));
  }
  console.log(dim('  Loopback-only. No TLS, no auth, no telemetry.'));
  console.log(dim('  Press Ctrl+C to stop.'));
  console.log('');

  // Stay alive until interrupted.
  await new Promise(() => {});
}

/**
 * Canonical list of files committed by the Sigil.
 * MUST match generate-sigil.mjs's MONITORED_FILES exactly.
 */
const MONITORED_FILES_FOR_SIGIL = [
  'cli.js',
  'src/detect.js',
  'src/conformance.js',
  'src/errors.js',
  'src/engines/ed25519-receipt.js',
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
  'src/context/live-context.js',
  'src/output/terminal.js',
  'src/output/json.js',
  'src/output/html-report.js',
  'src/util/canonical.js',
  'src/util/hex.js',
  'src/util/jwks.js',
  'src/util/audit-log.js',
  'src/util/fips.js',
  'src/util/voprf-crypto.js',
  'src/util/voprf-crypto-v2.js',
];

function selfCheckResult(sigil) {
  if (!sigil) return { canonical: false };
  const bufs = [];
  for (const f of MONITORED_FILES_FOR_SIGIL) {
    try { bufs.push(readFileSync(join(__dirname, f))); } catch { /* missing => modified */ }
  }
  const installedSourceBytes = Buffer.concat(bufs);
  return selfCheck({ sigil, installedSourceBytes });
}

async function main() {
  const opts = parseArgs();

  if (opts.help) { printHelp(); process.exit(0); }
  if (opts.version) { console.log(PKG.version); process.exit(0); }
  if (opts.capabilities) { printCapabilities(); process.exit(0); }
  if (opts.pinSigil) enforcePinSigil(opts.pinSigil);

  // Subcommands
  if (opts.subcommand === 'init') {
    const result = await runInit({ framework: opts.frameworkOverride, org: opts.attestOrg, force: opts.force });
    if (result.status === 'exists') {
      console.error(yellow(result.message));
      process.exit(1);
    }
    console.log('');
    if (!process.env.CI && !process.env.NO_COLOR) {
      console.log(renderTerminalSigil(result.key.pubHex));
      console.log('');
    }
    console.log(`${green('✓')} ${bold('Veritas Acta initialized')}`);
    console.log(`  Directory: ${result.vaDir}`);
    console.log(`  Kid:       ${result.key.kid}`);
    console.log(`  Pubkey:    ${result.key.pubHex}`);
    if (result.detection) {
      console.log(`  Framework: ${green(result.detection.framework)} (${result.detection.language})`);
    } else {
      console.log(`  Framework: ${yellow('not auto-detected')} — see manual setup below`);
    }
    console.log('');
    console.log(bold('Next steps:'));
    for (const line of buildNextSteps(result.detection, result.config)) {
      console.log(`  ${line}`);
    }
    console.log('');
    console.log(dim(`Protocol: https://veritasacta.com`));
    console.log(dim(`Managed:  https://scopeblind.com (optional)`));
    console.log('');
    process.exit(0);
  }

  if (opts.subcommand === 'proxy') {
    const keyPath = opts.attestKey || join(process.cwd(), '.veritasacta', 'attester.json');
    const code = await runProxy({
      target: opts.proxyTarget,
      key: keyPath,
      receiptsDir: opts.proxyReceiptsDir,
    });
    process.exit(code);
  }

  if (opts.subcommand === 'daemon') {
    await runDaemon({
      socket: opts.daemonSocket,
      key: opts.attestKey,
      receiptsDir: opts.proxyReceiptsDir,
    });
    return;
  }

  if (opts.subcommand === 'prompt') {
    await runPromptVerify(opts);
    return;
  }

  if (opts.subcommand === 'chain') {
    await runChainExplore(opts);
    return;
  }

  if (opts.subcommand === 'compliance') {
    await runCompliance(opts);
    return;
  }

  if (opts.subcommand === 'dashboard') {
    await runDashboard(opts);
    return;
  }

  if (opts.selfCheck) { await runSelfCheck(); return; }
  if (opts.selfTest) { await runSelfTest(opts); return; }
  if (opts.replayChain) { await runReplayChain(opts); return; }
  if (opts.diff) { await runDiff(opts); return; }

  // --attest without a file: emit a standalone canonical attestation
  if (opts.attest && !opts.file && !opts.stdin) {
    const sigil = loadSigil();
    const r = selfCheckResult(sigil);
    const att = buildCanonicalAttestation({
      sigil, canonical: r.canonical, org: opts.attestOrg, keyPath: opts.attestKey,
    });
    const output = JSON.stringify(att, null, 2);
    if (opts.output) { writeFileSync(opts.output, output); console.error(dim(`wrote ${opts.output}`)); }
    else console.log(output);
    process.exit(0);
  }

  const raw = await readInput(opts);
  if (raw === null) {
    console.error(red('Error: no input file specified.'));
    console.error('Usage: npx @veritasacta/verify <file.json> [--key <hex>]');
    process.exit(2);
  }

  let input;
  try {
    input = JSON.parse(raw);
  } catch (e) {
    console.error(red(`Error: invalid JSON: ${e.message}`));
    process.exit(2);
  }

  if (opts.strict && opts.allowEmbeddedKey) {
    console.error(yellow('Warning: --strict overrides --allow-embedded-key (embedded keys always rejected in strict mode).'));
    opts.allowEmbeddedKey = false;
  }

  // FIPS enforcement (if set, checks algorithm compliance before verify)
  if (opts.fips) {
    const claimedAlgo = input.algorithm || input.signature?.alg || 'ed25519';
    const f = fipsStatus(claimedAlgo);
    if (!f.approved) {
      const result = {
        valid: false,
        error: 'unsupported_algorithm',
        detail: `FIPS mode: ${f.reason}`,
        format: 'fips-rejected',
      };
      if (opts.json) console.log(JSON.stringify(result, null, 2));
      else {
        console.error(red(`✗ FIPS mode rejects algorithm "${claimedAlgo}"`));
        console.error(yellow(f.reason));
      }
      process.exit(2);
    }
  }

  let result = await dispatch(input, opts);
  result = applyTierGate(result, opts.tier);

  // Attach error metadata
  if (result.error) {
    const meta = getError(result.error);
    if (meta) result.errorMeta = meta;
  }

  // Audit log
  if (opts.auditLog) {
    const sigil = loadSigil();
    try {
      appendAuditEntry(opts.auditLog, result, { sigil, org: opts.attestOrg });
    } catch (e) {
      console.error(yellow(`Warning: failed to append audit log: ${e.message}`));
    }
  }

  // Audit report (HTML)
  if (opts.auditReport) {
    const sigil = loadSigil();
    let attestation = null;
    if (opts.attest) {
      const r = selfCheckResult(sigil);
      attestation = buildCanonicalAttestation({
        sigil, canonical: r.canonical, org: opts.attestOrg, keyPath: opts.attestKey,
      });
    }
    const html = renderHtmlReport({ result, sigil, attestation });
    if (opts.output) {
      writeFileSync(opts.output, html);
      console.error(dim(`wrote ${opts.output}`));
    } else {
      console.log(html);
    }
    process.exit(result.valid ? 0 : exitCodeFor(result.error));
  }

  // Output
  if (opts.json) {
    const obj = JSON.parse(formatAsJson(result));
    // Optionally attach emitted artifacts
    if (opts.attest) {
      const sigil = loadSigil();
      const r = selfCheckResult(sigil);
      obj.canonical_attestation = buildCanonicalAttestation({
        sigil, canonical: r.canonical, org: opts.attestOrg, keyPath: opts.attestKey,
      });
    }
    if (opts.emitVerificationReceipt && result.valid) {
      const sigil = loadSigil();
      obj.verification_receipt = buildVerificationReceipt({
        subjectResult: result, sigil, keyPath: opts.attestKey,
      });
    }
    console.log(JSON.stringify(obj, null, 2));
  } else {
    if (result.format === 'knowledge-unit') console.log(formatKuResult(result, opts));
    else if (result.total !== undefined) console.log(formatBundleResult(result, opts));
    else console.log(formatReceiptResult(result, opts));

    // Surface attestation artifacts separately for terminal mode
    if (opts.attest) {
      const sigil = loadSigil();
      const r = selfCheckResult(sigil);
      const att = buildCanonicalAttestation({
        sigil, canonical: r.canonical, org: opts.attestOrg, keyPath: opts.attestKey,
      });
      if (opts.output) {
        writeFileSync(opts.output, JSON.stringify(att, null, 2));
        console.error(dim(`wrote canonical attestation to ${opts.output}`));
      } else {
        console.log(`${bold('Canonical attestation:')}`);
        console.log(JSON.stringify(att, null, 2));
        console.log('');
      }
    }
    if (opts.emitVerificationReceipt && result.valid) {
      const sigil = loadSigil();
      const vr = buildVerificationReceipt({ subjectResult: result, sigil, keyPath: opts.attestKey });
      console.log(`${bold('Verification receipt:')}`);
      console.log(JSON.stringify(vr, null, 2));
      console.log('');
    }
  }

  // Exit. A result flagged `_partial: true` has NOT been fully
  // cryptographically verified (e.g. VOPRF tokens whose DLEQ proof
  // check is structural-only in this release). By default we fail
  // closed with exit code 2 (undecidable). Callers who explicitly
  // want the partial result surfaced as "valid" can opt in with
  // --allow-partial-voprf.
  if (result.valid) {
    if (result._partial && !opts.allowPartialVoprf) {
      if (!opts.json) {
        console.error(red(
          '\n  Exit 2: partial verification is not a full cryptographic check.\n' +
          '  Pass --allow-partial-voprf to treat a partial result as valid.\n'
        ));
      }
      process.exit(2);
    }
    process.exit(0);
  }
  process.exit(exitCodeFor(result.error));
}

main().catch((e) => {
  console.error(red(`Fatal error: ${e.message}`));
  if (process.env.DEBUG) console.error(e.stack);
  process.exit(2);
});
