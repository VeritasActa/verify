/** Browser adapter around the same detector, receipt engine and error registry as the CLI. No I/O. */
import { detectFormat } from './detect.js';
import { verifyReceipt } from './engines/ed25519-receipt.js';
import { exitCodeFor } from './errors.js';
import { parseReceiptJson } from './util/strict-json.js';

const SUPPORTED = new Set(['ed25519-passport', 'ed25519-receipt-v2', 'ed25519-receipt-v1', 'ed25519-browser-legacy']);
export async function verifyReceiptText(text, publicKey = '') {
  const unchecked = (error, detail, format = 'unknown') => ({ valid: false, status: 'not_checked', error, detail, format });
  let input;
  try { input = parseReceiptJson(text); }
  catch (e) { return unchecked(e.code, e.message); }
  const detected = detectFormat(input);
  if (!SUPPORTED.has(detected.mode) || detected.hasSelectiveDisclosure) {
    return unchecked('unsupported_format', 'This browser checks individual Ed25519 receipts. Use the CLI for bundles and specialist profiles.', detected.mode);
  }
  const key = publicKey.trim();
  if (key && !/^[0-9a-f]{64}$/i.test(key)) return unchecked('malformed_hex', 'Supply a 64-character hexadecimal Ed25519 public key.', detected.mode);
  try {
    const result = await verifyReceipt(input, detected.mode, { publicKey: key || undefined, allowEmbeddedKey: false });
    return { ...result, mode: detected.mode, status: result.valid ? 'valid' : exitCodeFor(result.error) === 1 ? 'invalid' : 'not_checked' };
  } catch {
    return unchecked('malformed_encoding', 'The receipt could not be interpreted safely.', detected.mode);
  }
}
