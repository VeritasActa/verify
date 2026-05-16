/**
 * Universal MCP proxy (receipt-signing transparent wrapper).
 *
 * Usage:
 *   veritasacta proxy --target "node my-mcp-server.js"
 *   veritasacta proxy --target "python server.py" --key ~/.veritasacta/attester.json
 *
 * The proxy spawns the target MCP server as a child process and relays
 * stdin/stdout between the parent (Claude Code / Cursor / etc.) and the
 * child. On each `tools/call` JSON-RPC request, the proxy signs a
 * decision receipt using the configured signing key. Receipts are
 * written to `.veritasacta/receipts/` (or a path specified by
 * --receipts-dir).
 *
 * No changes are required in either the MCP server or the host agent.
 * This matches the Signet proxy pattern documented at
 * https://github.com/Prismer-AI/signet.
 *
 * MCP protocol reference: https://spec.modelcontextprotocol.io/
 *
 * @module verify-cli/src/engines/proxy
 * @license Apache-2.0
 */

import { spawn } from 'node:child_process';
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
} from 'node:fs';
import { join } from 'node:path';
import { sign, createPrivateKey, createHash } from 'node:crypto';
import { canonicalize } from '../util/canonical.js';

/**
 * Load or refuse — the proxy requires a signing key to be provided.
 *
 * @param {string} keyPath
 * @returns {{kid: string, privateKey: import('node:crypto').KeyObject, pubHex: string}}
 */
function loadKey(keyPath) {
  if (!existsSync(keyPath)) {
    throw new Error(`No signing key at ${keyPath}. Run \`veritasacta init\` to create one.`);
  }
  const data = JSON.parse(readFileSync(keyPath, 'utf-8'));
  return {
    kid: data.kid,
    privateKey: createPrivateKey({
      key: Buffer.from(data.privateDer, 'hex'),
      format: 'der',
      type: 'pkcs8',
    }),
    pubHex: data.pubHex,
  };
}

/**
 * Sign a payload with Ed25519 + JCS canonicalization.
 */
function signPayload(privateKey, payload) {
  const canonical = canonicalize(payload);
  const sig = sign(null, Buffer.from(canonical, 'utf-8'), privateKey);
  return sig.toString('hex');
}

/**
 * @typedef {Object} ProxyOptions
 * @property {string} target                     command + args (joined with space)
 * @property {string} [key]                      key file path
 * @property {string} [receiptsDir]              directory to write receipts into
 * @property {string} [receiptsJsonl]            append-only JSONL log path
 * @property {string} [issuerId]                 issuer identifier (defaults to kid)
 * @property {string} [policyId]                 policy identifier to embed
 * @property {string} [serverKey]                Server-side signing key file (enables bilateral cosign)
 * @property {boolean} [bilateral]               If true, require serverKey and attach a cosignature per request
 * @property {boolean} [scrubSecrets]            Redact probable-secret argument values outbound + flag on receipt
 * @property {string} [traceId]                  Optional trace_id to stamp on every receipt (workflow grouping)
 */

/** Key names considered secret for --scrub-secrets. */
const SECRET_KEY_NAMES = new Set([
  'api_key', 'apikey', 'api-key',
  'token', 'access_token', 'auth_token', 'bearer',
  'password', 'passwd', 'pwd',
  'secret', 'client_secret',
  'authorization', 'x-api-key',
  'private_key', 'privatekey',
]);

function isSecretKeyName(name) {
  return SECRET_KEY_NAMES.has(String(name).toLowerCase());
}

/**
 * Walk an object tree and, for any key matching the secret-key-name set,
 * replace the value with a redacted marker. Returns { scrubbed, detected: string[] }.
 */
function scrubSecretArgs(args) {
  const detected = [];
  function walk(node, pathParts) {
    if (node && typeof node === 'object' && !Array.isArray(node)) {
      const out = {};
      for (const [k, v] of Object.entries(node)) {
        if (isSecretKeyName(k) && (typeof v === 'string' || typeof v === 'number')) {
          detected.push([...pathParts, k].join('.'));
          out[k] = 'REDACTED_BY_PROXY';
        } else {
          out[k] = walk(v, [...pathParts, k]);
        }
      }
      return out;
    }
    if (Array.isArray(node)) {
      return node.map((el, i) => walk(el, [...pathParts, String(i)]));
    }
    return node;
  }
  const scrubbed = walk(args, []);
  return { scrubbed, detected };
}

/**
 * Run the proxy: spawn target, intercept MCP tool-call requests, sign receipts.
 *
 * @param {ProxyOptions} opts
 * @returns {Promise<number>}  exit code of child process
 */
export async function runProxy(opts) {
  if (!opts.target) throw new Error('--target <command> is required');

  const keyPath = opts.key || join(process.cwd(), '.veritasacta', 'attester.json');
  const key = loadKey(keyPath);

  // Optional server-side key for bilateral cosign. If --bilateral is set
  // without --server-key, we fall back to the primary key (useful for
  // testing the envelope shape without a real second signer).
  let serverKey = null;
  if (opts.bilateral || opts.serverKey) {
    const serverKeyPath = opts.serverKey || keyPath;
    serverKey = loadKey(serverKeyPath);
    process.stderr.write(
      `[veritasacta proxy] bilateral mode enabled, server kid=${serverKey.kid}\n`
    );
  }

  const receiptsDir = opts.receiptsDir || join(process.cwd(), '.veritasacta', 'receipts');
  const receiptsJsonl = opts.receiptsJsonl || join(process.cwd(), '.veritasacta', 'receipts.jsonl');
  mkdirSync(receiptsDir, { recursive: true });

  const issuerId = opts.issuerId || key.kid;
  const policyId = opts.policyId || 'veritasacta:proxy:default';
  const traceId = opts.traceId || null;

  // Split the target command into executable + args
  const tokens = opts.target.trim().split(/\s+/);
  const cmd = tokens[0];
  const args = tokens.slice(1);

  // Spawn child with piped stdio so we can intercept
  const child = spawn(cmd, args, {
    stdio: ['pipe', 'pipe', 'inherit'],
  });

  let sequence = 0;
  let previousReceiptHash = null;

  // Buffered readline across JSON-RPC frames (MCP uses newline-delimited JSON)
  let inBuffer = '';
  process.stdin.on('data', (chunk) => {
    inBuffer += chunk.toString('utf-8');
    let newlineIdx;
    while ((newlineIdx = inBuffer.indexOf('\n')) !== -1) {
      const line = inBuffer.slice(0, newlineIdx);
      inBuffer = inBuffer.slice(newlineIdx + 1);
      if (line.trim().length === 0) {
        child.stdin.write('\n');
        continue;
      }

      // Try to parse as JSON-RPC
      let message;
      try { message = JSON.parse(line); } catch {
        // Not JSON — pass through unchanged
        child.stdin.write(line + '\n');
        continue;
      }

      // Is this a tools/call request?
      if (message && message.method === 'tools/call' && message.params) {
        sequence++;
        const toolName = message.params.name || 'unknown';
        let toolArgs = message.params.arguments || {};
        let scrubDetected = [];
        let forwardedMessage = message;

        if (opts.scrubSecrets) {
          const { scrubbed, detected } = scrubSecretArgs(toolArgs);
          if (detected.length > 0) {
            scrubDetected = detected;
            toolArgs = scrubbed;
            forwardedMessage = {
              ...message,
              params: { ...message.params, arguments: scrubbed },
            };
            process.stderr.write(
              `[veritasacta proxy] --scrub-secrets redacted ${detected.length} arg(s) in rcpt_${sequence}: ${detected.join(', ')}\n`
            );
          }
        }

        // Compute tool input hash over POSSIBLY-SCRUBBED args (secrets never
        // enter the receipt even as a hash of the real value).
        const argStr = JSON.stringify(toolArgs, Object.keys(toolArgs).sort());
        const toolInputHash = 'sha256:' + createHash('sha256').update(argStr, 'utf-8').digest('hex');

        const payload = {
          type: 'veritasacta:proxy:decision',
          spec: 'draft-farley-acta-signed-receipts-03',
          tool_name: toolName,
          tool_input_hash: toolInputHash,
          decision: 'allow',
          policy_id: policyId,
          issued_at: new Date().toISOString(),
          issuer_id: issuerId,
          sequence,
          previousReceiptHash,
          ...(traceId ? { trace_id: traceId } : {}),
          ...(scrubDetected.length > 0 ? { scrub_detected: scrubDetected } : {}),
        };

        const sig = signPayload(key.privateKey, payload);
        const receipt = {
          payload,
          signature: { alg: 'EdDSA', kid: key.kid, sig },
        };

        // Bilateral cosign: server independently signs the same canonical
        // payload. Both signatures verify against the same bytes; an
        // attacker who compromises one key alone cannot produce a
        // bilaterally-valid receipt.
        if (serverKey) {
          const coSig = signPayload(serverKey.privateKey, payload);
          receipt.cosignatures = [
            { alg: 'EdDSA', kid: serverKey.kid, sig: coSig },
          ];
        }

        // Update chain hash
        const canonical = canonicalize(payload);
        previousReceiptHash = 'sha256:' + createHash('sha256').update(canonical, 'utf-8').digest('hex');

        // Persist
        const receiptFile = join(receiptsDir, `rcpt_${String(sequence).padStart(6, '0')}.json`);
        writeFileSync(receiptFile, JSON.stringify(receipt, null, 2));
        try {
          writeFileSync(receiptsJsonl, JSON.stringify(receipt) + '\n', { flag: 'a' });
        } catch {}

        // Log to stderr so we don't interfere with MCP stdout
        const modeTag = serverKey ? ' [bilateral]' : '';
        process.stderr.write(
          `[veritasacta proxy] rcpt_${sequence} signed (${toolName}) kid=${key.kid}${modeTag}\n`
        );

        // Forward the (possibly scrubbed) message to the child.
        child.stdin.write(JSON.stringify(forwardedMessage) + '\n');
        continue;
      }

      // Pass through the original message to the child unchanged
      child.stdin.write(line + '\n');
    }
  });

  // Forward child stdout to parent stdout
  child.stdout.pipe(process.stdout);

  // Error handling
  child.on('error', (err) => {
    process.stderr.write(`[veritasacta proxy] child error: ${err.message}\n`);
  });

  return new Promise((resolve) => {
    child.on('close', (code) => {
      process.stderr.write(`[veritasacta proxy] child exited with code ${code}; ${sequence} receipt(s) signed\n`);
      resolve(code || 0);
    });
  });
}
