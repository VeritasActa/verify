import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';

const packed = JSON.parse(readFileSync('packed.json', 'utf8'))[0];
const dir = mkdtempSync(join(tmpdir(), 'scopeblind-release-check-'));
// The independently documented demonstration pin; never extract a trust pin from
// the receipt under test. This is public sample material, not a production issuer.
const sampleKey = 'ebb8cf3efc78717c50e7c438c0ad5498f8fa4e09607fea1e030ac129b5965225';

try {
  execFileSync('npm', [
    'install', '--prefix', dir, '--ignore-scripts', '--no-audit', '--no-fund',
    resolve(packed.filename),
  ], { stdio: 'inherit' });
  const packageDir = join(dir, 'node_modules', '@veritasacta/verify');
  const bin = join(packageDir, 'cli.js');
  for (const args of [['--help'], ['--self-check'], ['--self-test']]) {
    execFileSync(process.execPath, [bin, ...args], {
      cwd: dir, stdio: 'inherit', timeout: 30000,
    });
  }

  const receipt = JSON.parse(readFileSync(join(packageDir, 'samples/current-receipt.json'), 'utf8'));
  writeFileSync(join(dir, 'current-receipt.json'), JSON.stringify(receipt));
  const changed = structuredClone(receipt);
  changed.payload.decision = 'deny';
  writeFileSync(join(dir, 'changed-receipt.json'), JSON.stringify(changed));

  for (const { name, args, status, outcome } of [
    { name: 'documented sample', args: ['current-receipt.json', '--key', sampleKey], status: 0, outcome: 'valid' },
    { name: 'missing independent key', args: ['current-receipt.json'], status: 2, outcome: 'undecidable' },
    { name: 'wrong expected key', args: ['current-receipt.json', '--key', '11'.repeat(32)], status: 1, outcome: 'invalid' },
    { name: 'changed signed payload', args: ['changed-receipt.json', '--key', sampleKey], status: 1, outcome: 'invalid' },
  ]) {
    const run = spawnSync(process.execPath, [bin, ...args, '--json'], {
      cwd: dir, encoding: 'utf8', timeout: 30000,
    });
    if (run.error) throw run.error;
    assert.equal(run.status, status, `${name}: ${run.stderr || run.stdout}`);
    assert.equal(JSON.parse(run.stdout).outcome, outcome, name);
    console.log(`Packed receipt check: ${name} -> ${outcome} (exit ${status}).`);
  }
  execFileSync(process.execPath, [join(packageDir, 'test/conformance.js')], {
    cwd: dir, stdio: 'inherit', timeout: 30000,
  });
  console.log('The packed package installs and its documented verification flow runs in an empty directory.');
} finally {
  rmSync(dir, { recursive: true, force: true });
}
