import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
const result = await build({ entryPoints: ['src/browser.js'], bundle: true, platform: 'browser', format: 'esm', target: 'es2022', minify: true, legalComments: 'inline', write: false });
const bytes = result.outputFiles[0].contents;
const hash = createHash('sha256').update(bytes).digest('hex');
const metadata = JSON.stringify({ version: JSON.parse(readFileSync('package.json')).version, sha256: hash, entry: 'src/browser.js', engine: 'src/engines/ed25519-receipt.js' }, null, 2) + '\n';
const licenses = ['@noble/curves', '@noble/hashes'].map(name => `${name}\n\n${readFileSync(`node_modules/${name}/LICENSE`, 'utf8')}`).join('\n\n');
if (process.argv.includes('--check')) {
  if (!Buffer.from(bytes).equals(readFileSync('browser/receipt-verifier.js')) || metadata !== readFileSync('browser/build.json', 'utf8')) throw Error('Browser build differs from the checked source. Run npm run build:browser.');
  if (licenses !== readFileSync('browser/LICENSES.txt', 'utf8')) throw Error('Browser license notices differ.');
} else {
  mkdirSync('browser', { recursive: true });
  writeFileSync('browser/receipt-verifier.js', bytes);
  writeFileSync('browser/build.json', metadata);
  writeFileSync('browser/LICENSES.txt', licenses);
}
console.log(`Browser engine SHA-256 ${hash}`);
