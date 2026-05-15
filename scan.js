#!/usr/bin/env node
'use strict';
/*
 * npm-compromise-scanner
 *
 * Scan a directory tree for npm packages compromised in a supply-chain
 * incident, given a CSV of affected packages.
 *
 * Checks four sources:
 *   - package.json          (declared dependencies)
 *   - package-lock.json     (npm-resolved versions)
 *   - yarn.lock             (yarn-resolved versions, classic v1 + berry)
 *   - node_modules/         (packages actually installed on disk)
 *
 * Pure Node.js stdlib, zero dependencies.
 *
 * Usage:  node scan.js <scan-dir> <affected-packages.csv> [--skip-node-modules]
 */
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------- args
const args = process.argv.slice(2);
const flags = new Set(args.filter(a => a.startsWith('-')));
const positional = args.filter(a => !a.startsWith('-'));

function printHelp() {
  console.log(`npm-compromise-scanner

Scan a directory tree for npm packages compromised in a supply-chain
incident, given a CSV of affected packages.

Usage:
  node scan.js <scan-dir> <affected-packages.csv> [options]

Options:
  --skip-node-modules   Scan only manifests/lockfiles, skip installed node_modules
  --help, -h            Show this help

Exit codes:
  0  clean - no confirmed compromised package found
  1  one or more confirmed compromised name@version present
  2  usage / input error

CSV format:
  Header row required. Recognised columns (case-insensitive):
    Ecosystem | Namespace | Name | Version
  Only rows where Ecosystem is "npm" (or absent) are scanned. A "Name"
  that already contains a scope ("@scope/pkg") is used as-is.`);
}

if (flags.has('--help') || flags.has('-h')) { printHelp(); process.exit(0); }

// Both arguments are required. The tool has no defaults and never assumes
// a location on the host machine - the folder and CSV must be passed in.
const errors = [];
if (!positional[0]) errors.push('no folder to scan provided');
if (!positional[1]) errors.push('no CSV of affected packages provided');
if (errors.length) {
  for (const e of errors) console.error(`ERROR: ${e}`);
  console.error('');
  printHelp();
  process.exit(2);
}

const ROOT = path.resolve(positional[0]);
const CSV = path.resolve(positional[1]);
const SKIP_NM = flags.has('--skip-node-modules');

if (!fs.existsSync(ROOT) || !fs.statSync(ROOT).isDirectory()) {
  console.error(`ERROR: scan dir not found or not a directory: ${ROOT}`);
  process.exit(2);
}
if (!fs.existsSync(CSV) || !fs.statSync(CSV).isFile()) {
  console.error(`ERROR: CSV file not found: ${CSV}`);
  process.exit(2);
}

// ---------------------------------------------------------------- CSV parse
// Minimal RFC-4180-ish line parser: handles quoted fields and escaped quotes.
function parseCsvLine(line) {
  const out = [];
  let cur = '', inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQ) {
      if (c === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; } else inQ = false;
      } else cur += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { out.push(cur); cur = ''; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

const csvRows = fs.readFileSync(CSV, 'utf8').split(/\r?\n/).filter(r => r.trim().length);
if (!csvRows.length) { console.error('ERROR: CSV is empty'); process.exit(2); }

const headers = parseCsvLine(csvRows[0]).map(h => h.trim().toLowerCase());
const findCol = (...names) => {
  for (const n of names) { const i = headers.indexOf(n); if (i >= 0) return i; }
  return -1;
};
const cEco = findCol('ecosystem', 'type');
const cNs = findCol('namespace', 'scope');
const cName = findCol('name', 'package', 'package name', 'packagename');
const cVer = findCol('version', 'affected version', 'affectedversion');

if (cName < 0 || cVer < 0) {
  console.error(`ERROR: CSV must have "Name" and "Version" columns. Found: ${headers.join(', ')}`);
  process.exit(2);
}

// affected: npm full package name -> Set(versions). nonNpm: informational only.
const affected = new Map();
const nonNpm = [];
for (let i = 1; i < csvRows.length; i++) {
  const f = parseCsvLine(csvRows[i]);
  const eco = (cEco >= 0 ? (f[cEco] || '') : 'npm').trim().toLowerCase();
  const name = (f[cName] || '').trim();
  const version = (f[cVer] || '').trim();
  if (!name || !version) continue;
  if (eco && eco !== 'npm') { nonNpm.push(`${eco}: ${name}@${version}`); continue; }
  const ns = (cNs >= 0 ? (f[cNs] || '') : '').trim();
  let full;
  if (name.startsWith('@') && name.includes('/')) full = name;        // already scoped
  else if (ns) full = `${ns.startsWith('@') ? ns : '@' + ns}/${name}`; // namespace col
  else full = name;                                                    // unscoped
  if (!affected.has(full)) affected.set(full, new Set());
  affected.get(full).add(version);
}

if (!affected.size) {
  console.error('ERROR: no npm packages parsed from CSV - check the format (see --help).');
  process.exit(2);
}
const hit = (name, version) => affected.has(name) && affected.get(name).has(version);

// ---------------------------------------------------------------- walk tree
const manifests = [];   // { file, kind: 'pkg' | 'lock' }
const yarnLocks = [];
const nmPkgJson = [];   // package.json paths inside node_modules
const seen = new Set();

function walk(dir, inNM) {
  let rp; try { rp = fs.realpathSync(dir); } catch { return; }
  if (seen.has(rp)) return;            // guard against symlink loops
  seen.add(rp);
  let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const fp = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === '.git') continue;
      const nextNM = inNM || e.name === 'node_modules';
      if (nextNM && SKIP_NM) continue;
      walk(fp, nextNM);
    } else if (e.name === 'package.json') {
      if (inNM) nmPkgJson.push(fp);
      else manifests.push({ file: fp, kind: 'pkg' });
    } else if (e.name === 'package-lock.json' && !inNM) {
      manifests.push({ file: fp, kind: 'lock' });
    } else if (e.name === 'yarn.lock' && !inNM) {
      yarnLocks.push(fp);
    }
  }
}
walk(ROOT, false);

// ---------------------------------------------------------------- scanners
const confirmed = [];   // exact compromised name@version present
const nameMatch = [];   // affected name declared as a dep, version is a range
const parseErrors = [];

// package.json - declared dependencies
function scanPkg(file, j) {
  for (const g of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const d = j[g];
    if (!d || typeof d !== 'object') continue;
    for (const [name, spec] of Object.entries(d)) {
      if (!affected.has(name)) continue;
      const s = String(spec);
      const cleaned = s.replace(/^[\^~>=<\s]+/, '');
      if (/^\d+\.\d+\.\d+/.test(s) && affected.get(name).has(cleaned)) {
        confirmed.push({ name, version: cleaned, where: `package.json (${g}, pinned)`, file });
      } else {
        nameMatch.push({ name, spec: s, where: `package.json (${g})`, file, affected: [...affected.get(name)] });
      }
    }
  }
}

// package-lock.json - resolved versions (lockfileVersion 1, 2 and 3)
function scanLock(file, j) {
  if (j.packages && typeof j.packages === 'object') {
    for (const [k, info] of Object.entries(j.packages)) {
      if (!k || !info || !info.version) continue;
      const i = k.lastIndexOf('node_modules/');
      const name = i >= 0 ? k.slice(i + 'node_modules/'.length) : k;
      if (hit(name, info.version)) {
        confirmed.push({ name, version: info.version, where: 'package-lock.json (resolved)', file });
      }
    }
  }
  (function rec(deps) {
    if (!deps || typeof deps !== 'object') return;
    for (const [name, info] of Object.entries(deps)) {
      if (!info || typeof info !== 'object') continue;
      if (info.version && hit(name, info.version)) {
        confirmed.push({ name, version: info.version, where: 'package-lock.json (resolved)', file });
      }
      if (info.dependencies) rec(info.dependencies);
    }
  })(j.dependencies);
}

// yarn.lock - resolved versions (classic v1 and berry v2+)
function scanYarn(file) {
  let txt;
  try { txt = fs.readFileSync(file, 'utf8'); }
  catch (e) { parseErrors.push(`${file}: ${e.message}`); return; }
  let curNames = [];
  for (const line of txt.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith('#')) continue;
    if (!/^\s/.test(line)) {
      // header: one or more comma-separated specs, ends with ':'
      curNames = [];
      const hdr = line.replace(/:\s*$/, '');
      if (hdr === '__metadata') continue;
      for (let spec of hdr.split(',')) {
        spec = spec.trim().replace(/^"|"$/g, '');
        if (!spec) continue;
        let name;
        const npmIdx = spec.indexOf('@npm:');
        if (npmIdx > 0) {
          name = spec.slice(0, npmIdx);
        } else {
          const at = spec.lastIndexOf('@');
          name = at > 0 ? spec.slice(0, at) : spec;
        }
        if (affected.has(name)) curNames.push(name);
      }
    } else if (curNames.length) {
      const m = line.match(/^\s+version:?\s+"?([^"\s]+)"?/);
      if (m) {
        for (const name of curNames) {
          if (hit(name, m[1])) confirmed.push({ name, version: m[1], where: 'yarn.lock (resolved)', file });
        }
        curNames = [];
      }
    }
  }
}

for (const { file, kind } of manifests) {
  let j;
  try { j = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { parseErrors.push(`${file}: ${e.message}`); continue; }
  if (kind === 'pkg') scanPkg(file, j);
  else scanLock(file, j);
}
for (const yl of yarnLocks) scanYarn(yl);

// node_modules - packages actually installed on disk (authoritative)
let nmScanned = 0;
for (const file of nmPkgJson) {
  let j;
  try { j = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { continue; }
  nmScanned++;
  if (j && j.name && j.version && hit(j.name, j.version)) {
    confirmed.push({ name: j.name, version: j.version, where: 'INSTALLED in node_modules', file });
  }
}

// ---------------------------------------------------------------- report
const dedupe = a => {
  const s = new Set(), o = [];
  for (const x of a) {
    const k = `${x.file}|${x.name}|${x.version || x.spec}|${x.where}`;
    if (!s.has(k)) { s.add(k); o.push(x); }
  }
  return o;
};
const C = dedupe(confirmed);
const N = dedupe(nameMatch);
const pairs = [...affected.values()].reduce((a, s) => a + s.size, 0);

console.log('=== npm-compromise-scanner ===');
console.log(`Scan dir : ${ROOT}`);
console.log(`CSV      : ${CSV}`);
console.log(`Mode     : ${SKIP_NM ? 'manifests + lockfiles only' : 'manifests + lockfiles + installed node_modules'}`);
console.log('');
console.log('=== SCAN SUMMARY ===');
console.log(`Affected npm packages: ${affected.size} names / ${pairs} name@version pairs`);
if (nonNpm.length) console.log(`Non-npm CSV entries (out of scope): ${nonNpm.length}`);
console.log(`Scanned: ${manifests.filter(m => m.kind === 'pkg').length} package.json, ` +
            `${manifests.filter(m => m.kind === 'lock').length} package-lock.json, ` +
            `${yarnLocks.length} yarn.lock, ${nmScanned} installed node_modules package.json`);
console.log(`Parse errors: ${parseErrors.length}`);
console.log('');

console.log('=== CONFIRMED: compromised name@version present ===');
if (!C.length) console.log('  NONE');
for (const f of C) console.log(`  [HIT] ${f.name}@${f.version}  (${f.where})\n        ${f.file}`);
console.log('');

console.log('=== DEPENDENCY NAME MATCHES (affected name declared, version is a range) ===');
if (!N.length) console.log('  NONE');
for (const f of N) {
  console.log(`  [NAME] ${f.name} "${f.spec}"  (${f.where})\n        ${f.file}`);
  console.log(`        compromised versions: ${f.affected.join(', ')}`);
}

if (nonNpm.length) {
  console.log('\n=== NON-NPM CSV ENTRIES (not scanned - pypi/composer/etc.) ===');
  nonNpm.forEach(e => console.log('  ' + e));
}
if (parseErrors.length) {
  console.log('\n=== PARSE ERRORS ===');
  parseErrors.forEach(e => console.log('  ' + e));
}

console.log('');
console.log(C.length
  ? `RESULT: ${C.length} confirmed match(es) - INVESTIGATE.`
  : 'RESULT: clean - no confirmed compromised package found.');

process.exit(C.length ? 1 : 0);
