// Run from verify with sibling Acta, .github and drafts checkouts. No network or credentials.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const check = process.argv.includes('--check');
const manifest = readFileSync('release-manifest.json', 'utf8');
const release = JSON.parse(manifest);
if (release.verifier.version !== JSON.parse(readFileSync('package.json')).version) throw Error('Package / release manifest mismatch');
const bundle = readFileSync('browser/receipt-verifier.js');
const build = readFileSync('browser/build.json', 'utf8');
if (JSON.parse(build).sha256 !== createHash('sha256').update(bundle).digest('hex')) throw Error('Bundle fingerprint mismatch');
const block = `<!-- release-manifest:start -->\nVerifier: **[${release.verifier.version}](${release.verifier.release_url})**. Status reviewed ${release.reviewed_at}.\n\n${release.standards.map(s=>`- [${s.name}-${s.revision}](${s.url}): ${s.status}${s.expired_at?` (expired ${s.expired_at})`:''}.`).join('\n')}\n\n${release.standards_notice}\n<!-- release-manifest:end -->`;
function output(path, bytes) {
  if (check) { if (!Buffer.from(bytes).equals(readFileSync(path))) throw Error(`Metadata drift: ${path}`); }
  else writeFileSync(path, bytes);
}
for (const path of ['README.md', '../Acta/README.md', '../.github/profile/README.md', '../drafts/README.md']) {
  const text = readFileSync(path, 'utf8');
  if (!text.includes('<!-- release-manifest:start -->')) throw Error(`Missing release block: ${path}`);
  output(path, text.replace(/<!-- release-manifest:start -->[\s\S]*?<!-- release-manifest:end -->/, block));
}
output('../Acta/public/release-manifest.json', manifest);
output('../Acta/public/receipt-verifier.js.txt', bundle);
output('../Acta/public/browser-build.json', build);
output('../Acta/public/verifier-licenses.txt', readFileSync('browser/LICENSES.txt'));
const sample = readFileSync('samples/current-receipt.json', 'utf8');
const key = readFileSync('samples/current-receipt-key.txt', 'utf8');
output('../Acta/public/current-receipt.json', sample);
output('../Acta/public/current-receipt-key.txt', key);
output('../Acta/public/receipt-sample.js.txt', `// Public demonstration only; not an independently authenticated issuer.\nexport const sample = ${sample.trim()};\nexport const key = ${JSON.stringify(key.trim())};\n`);
console.log(check ? 'Public metadata and browser artifact match.' : 'Synchronized public metadata and browser artifact.');
