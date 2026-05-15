'use strict';
// Smoke + behavior tests for the npm-compromise-scanner CLI.
// Uses the Node.js built-in test runner (node --test) - no extra dependencies.

const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const SCAN = path.join(__dirname, '..', 'scan.js');
const CSV = path.join(__dirname, '..', 'examples', '22-packages.csv');
const CLEAN = path.join(__dirname, 'fixtures', 'clean');
const COMPROMISED = path.join(__dirname, 'fixtures', 'compromised');

function run(args) {
  return spawnSync(process.execPath, [SCAN, ...args], { encoding: 'utf8' });
}

test('--version prints the package version', () => {
  const r = run(['--version']);
  assert.strictEqual(r.status, 0);
  assert.match(r.stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('--help shows usage, examples and exit codes', () => {
  const r = run(['--help']);
  assert.strictEqual(r.status, 0);
  assert.match(r.stdout, /Usage:/);
  assert.match(r.stdout, /Examples:/);
  assert.match(r.stdout, /Exit codes:/);
});

test('missing arguments exit 2 (MISUSE)', () => {
  const r = run([]);
  assert.strictEqual(r.status, 2);
});

test('missing CSV argument exits 2', () => {
  const r = run([CLEAN]);
  assert.strictEqual(r.status, 2);
});

test('nonexistent scan folder exits 2 with an actionable error', () => {
  const r = run([path.join(__dirname, 'no-such-dir'), CSV]);
  assert.strictEqual(r.status, 2);
  assert.match(r.stderr, /not found/);
});

test('nonexistent CSV exits 2 with an actionable error', () => {
  const r = run([CLEAN, path.join(__dirname, 'no-such.csv')]);
  assert.strictEqual(r.status, 2);
  assert.match(r.stderr, /not found/);
});

test('clean fixture scans clean (exit 0)', () => {
  const r = run([CLEAN, CSV, '--skip-node-modules', '--no-color']);
  assert.strictEqual(r.status, 0);
  assert.match(r.stdout, /RESULT: clean/);
});

test('compromised fixture is detected (exit 1)', () => {
  const r = run([COMPROMISED, CSV, '--skip-node-modules', '--no-color']);
  assert.strictEqual(r.status, 1);
  assert.match(r.stdout, /\[HIT] cross-stitch@1\.1\.7/);
});

test('--json emits valid JSON and reports the compromise', () => {
  const r = run([COMPROMISED, CSV, '--skip-node-modules', '--json']);
  assert.strictEqual(r.status, 1);
  const parsed = JSON.parse(r.stdout);
  assert.strictEqual(parsed.outcome, 'compromised');
  assert.ok(
    parsed.confirmed.some((c) => c.name === 'cross-stitch' && c.version === '1.1.7'),
    'confirmed[] should contain cross-stitch@1.1.7'
  );
});

test('--json on a clean tree reports outcome "clean"', () => {
  const r = run([CLEAN, CSV, '--skip-node-modules', '--json']);
  assert.strictEqual(r.status, 0);
  assert.strictEqual(JSON.parse(r.stdout).outcome, 'clean');
});

test('--json output carries no ANSI color codes', () => {
  const r = run([CLEAN, CSV, '--skip-node-modules', '--json']);
  // eslint-disable-next-line no-control-regex
  assert.doesNotMatch(r.stdout, /\x1b\[/);
});
