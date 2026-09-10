import assert from 'node:assert/strict';
import {
  mkdtempSync,
  mkdirSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  readSigilMonitoredSource,
  SIGIL_MONITORED_FILES,
} from '../../src/sigil-policy.js';

const packageRoot = resolve(fileURLToPath(new URL('../..', import.meta.url)));

function runtimeJavascriptFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = join(directory, entry.name);
    if (entry.isDirectory()) return runtimeJavascriptFiles(absolute);
    return entry.isFile() && entry.name.endsWith('.js') ? [absolute] : [];
  });
}

function fixture(files) {
  const root = mkdtempSync(join(tmpdir(), 'veritasacta-sigil-policy-'));
  for (const [path, value] of Object.entries(files)) {
    const absolute = join(root, path);
    mkdirSync(dirname(absolute), { recursive: true });
    writeFileSync(absolute, value);
  }
  return root;
}

test('Sigil monitored source preserves declared order', () => {
  const root = fixture({ 'a.txt': 'A', 'nested/b.txt': 'B' });
  try {
    assert.equal(
      readSigilMonitoredSource(root, ['nested/b.txt', 'a.txt']).toString(),
      'BA',
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('Sigil monitored source fails closed instead of sealing a reduced list', () => {
  const root = fixture({ 'a.txt': 'A' });
  try {
    assert.throws(
      () => readSigilMonitoredSource(root, ['a.txt', 'missing.txt']),
      (error) => error.code === 'SIGIL_MONITORED_SURFACE_INCOMPLETE'
        && error.message.includes('missing.txt'),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('Sigil commitment covers every shipped executable JavaScript module', () => {
  const executableFiles = [
    'cli.js',
    ...runtimeJavascriptFiles(join(packageRoot, 'src'))
      .map((path) => relative(packageRoot, path)),
  ].sort();
  const monitoredExecutableFiles = SIGIL_MONITORED_FILES
    .filter((path) => path === 'cli.js' || path.startsWith('src/'))
    .sort();
  assert.deepEqual(monitoredExecutableFiles, executableFiles);
});
