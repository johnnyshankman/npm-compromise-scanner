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
 */

// --- Node version guard (runs before requiring commander) -------------------
const MIN_NODE_MAJOR = 20;
if (Number(process.versions.node.split('.')[0]) < MIN_NODE_MAJOR) {
  process.stderr.write(
    `npm-compromise-scanner requires Node.js >= ${MIN_NODE_MAJOR} ` +
    `(found ${process.version}).\n`
  );
  process.exit(2);
}

const fs = require('fs');
const path = require('path');
const { Command } = require('commander');
const pkg = require('./package.json');

// --- Exit codes (POSIX-ish) -------------------------------------------------
const EXIT = {
  SUCCESS: 0,     // clean - no confirmed compromised package found
  HITS: 1,        // one or more confirmed compromised name@version present
  MISUSE: 2,      // bad arguments / unreadable input
  PERMISSION: 77, // permission denied reading an input
  SIGINT: 130,    // interrupted (Ctrl+C)
};

// --- Graceful Ctrl+C --------------------------------------------------------
process.on('SIGINT', () => {
  process.stderr.write('\nScan cancelled.\n');
  process.exit(EXIT.SIGINT);
});

// --- Color: TTY-aware, zero-dependency --------------------------------------
// Honors --no-color, the NO_COLOR convention (https://no-color.org) and
// FORCE_COLOR, and never emits escape codes when stdout is not a TTY.
function resolveColor(options) {
  if (options.color === false) return false;
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR) return true;
  return Boolean(process.stdout.isTTY);
}
function makeColorizer(enabled) {
  const c = (code) => (s) => (enabled ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  return {
    red: c('31'), green: c('32'), yellow: c('33'),
    cyan: c('36'), bold: c('1'), dim: c('2'),
  };
}

// --- Progress: stderr only, and only when stderr is a TTY -------------------
// Diagnostics go to stderr so they never pollute piped/redirected stdout.
function makeProgress() {
  const active = Boolean(process.stderr.isTTY);
  return {
    update(msg) { if (active) process.stderr.write(`\r\x1b[2K${msg}`); },
    clear() { if (active) process.stderr.write('\r\x1b[2K'); },
  };
}

// --- CSV parsing ------------------------------------------------------------
// Minimal RFC-4180-ish line parser: handles quoted fields and escaped quotes.
function parseCsvLine(line) {
  const out = [];
  let cur = '', inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQ) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; } else inQ = false;
      } else cur += ch;
    } else if (ch === '"') inQ = true;
    else if (ch === ',') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

// Parse the affected-packages CSV into a Map: npm full name -> Set(versions).
// Columns are matched by header name, so order/extra columns do not matter.
function parseAffectedCsv(csvText) {
  const rows = csvText.split(/\r?\n/).filter((r) => r.trim().length);
  if (!rows.length) throw new Error('CSV is empty');

  const headers = parseCsvLine(rows[0]).map((h) => h.trim().toLowerCase());
  const findCol = (...names) => {
    for (const n of names) { const i = headers.indexOf(n); if (i >= 0) return i; }
    return -1;
  };
  const cEco = findCol('ecosystem', 'type');
  const cNs = findCol('namespace', 'scope');
  const cName = findCol('name', 'package', 'package name', 'packagename');
  const cVer = findCol('version', 'affected version', 'affectedversion');
  if (cName < 0 || cVer < 0) {
    throw new Error(
      `CSV must have "Name" and "Version" columns. Found: ${headers.join(', ')}`
    );
  }

  const affected = new Map();
  const nonNpm = [];
  for (let i = 1; i < rows.length; i++) {
    const f = parseCsvLine(rows[i]);
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
  if (!affected.size) throw new Error('no npm packages parsed from CSV');
  return { affected, nonNpm };
}

// --- Directory walk ---------------------------------------------------------
// One pass: collect manifests + yarn.locks, plus node_modules package.json
// paths (unless skipped). Guards against symlink loops via realpath.
function walkTree(root, skipNodeModules, progress) {
  const manifests = [];   // { file, kind: 'pkg' | 'lock' }
  const yarnLocks = [];
  const nmPkgJson = [];
  const seen = new Set();

  (function walk(dir, inNM) {
    let rp; try { rp = fs.realpathSync(dir); } catch { return; }
    if (seen.has(rp)) return;
    seen.add(rp);
    if (seen.size % 500 === 0) progress.update(`Walking directory tree… ${seen.size} dirs`);
    let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const fp = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === '.git') continue;
        const nextNM = inNM || e.name === 'node_modules';
        if (nextNM && skipNodeModules) continue;
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
  })(root, false);

  return { manifests, yarnLocks, nmPkgJson };
}

// --- The scan ---------------------------------------------------------------
function runScan(scanDirArg, csvArg, options) {
  const color = makeColorizer(options.json ? false : resolveColor(options));
  const progress = makeProgress();
  const err = (msg) => process.stderr.write(color.red('Error: ') + msg + '\n');

  const ROOT = path.resolve(scanDirArg);
  const CSV = path.resolve(csvArg);

  // Validate inputs early, with actionable messages.
  try {
    if (!fs.statSync(ROOT).isDirectory()) {
      err(`scan path is not a directory: ${ROOT}`);
      return EXIT.MISUSE;
    }
  } catch (e) {
    if (e.code === 'EACCES') { err(`permission denied reading folder: ${ROOT}`); return EXIT.PERMISSION; }
    err(`folder to scan not found: ${ROOT}`);
    return EXIT.MISUSE;
  }

  let csvText;
  try {
    csvText = fs.readFileSync(CSV, 'utf8');
  } catch (e) {
    if (e.code === 'EACCES') { err(`permission denied reading CSV: ${CSV}`); return EXIT.PERMISSION; }
    err(`CSV of affected packages not found: ${CSV}`);
    return EXIT.MISUSE;
  }

  let affected, nonNpm;
  try {
    ({ affected, nonNpm } = parseAffectedCsv(csvText));
  } catch (e) {
    err(`could not parse CSV (${CSV}): ${e.message}`);
    process.stderr.write('       Expected a header row with at least "Name" and "Version" columns.\n');
    return EXIT.MISUSE;
  }
  const hit = (name, version) => affected.has(name) && affected.get(name).has(version);

  // Walk the tree.
  const { manifests, yarnLocks, nmPkgJson } = walkTree(ROOT, Boolean(options.skipNodeModules), progress);

  const confirmed = [];   // exact compromised name@version present
  const nameMatch = [];   // affected name declared as a dep, version is a range
  const parseErrors = [];

  // package.json - declared dependencies.
  const scanPkg = (file, j) => {
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
          nameMatch.push({ name, spec: s, where: `package.json (${g})`, file, affectedVersions: [...affected.get(name)] });
        }
      }
    }
  };

  // package-lock.json - resolved versions (lockfileVersion 1, 2 and 3).
  const scanLock = (file, j) => {
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
  };

  // yarn.lock - resolved versions (classic v1 and berry v2+).
  const scanYarn = (file) => {
    let txt;
    try { txt = fs.readFileSync(file, 'utf8'); }
    catch (e) { parseErrors.push(`${file}: ${e.message}`); return; }
    let curNames = [];
    for (const line of txt.split(/\r?\n/)) {
      if (!line.trim() || line.startsWith('#')) continue;
      if (!/^\s/.test(line)) {
        curNames = [];
        const hdr = line.replace(/:\s*$/, '');
        if (hdr === '__metadata') continue;
        for (let spec of hdr.split(',')) {
          spec = spec.trim().replace(/^"|"$/g, '');
          if (!spec) continue;
          let name;
          const npmIdx = spec.indexOf('@npm:');
          if (npmIdx > 0) name = spec.slice(0, npmIdx);
          else { const at = spec.lastIndexOf('@'); name = at > 0 ? spec.slice(0, at) : spec; }
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
  };

  for (const { file, kind } of manifests) {
    let j;
    try { j = JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch (e) { parseErrors.push(`${file}: ${e.message}`); continue; }
    if (kind === 'pkg') scanPkg(file, j);
    else scanLock(file, j);
  }
  for (const yl of yarnLocks) scanYarn(yl);

  // node_modules - packages actually installed on disk (authoritative).
  let nmScanned = 0;
  for (let idx = 0; idx < nmPkgJson.length; idx++) {
    if (idx % 2000 === 0) {
      progress.update(`Scanning installed packages… ${idx}/${nmPkgJson.length}`);
    }
    let j;
    try { j = JSON.parse(fs.readFileSync(nmPkgJson[idx], 'utf8')); }
    catch { continue; }
    nmScanned++;
    if (j && j.name && j.version && hit(j.name, j.version)) {
      confirmed.push({ name: j.name, version: j.version, where: 'INSTALLED in node_modules', file: nmPkgJson[idx] });
    }
  }
  progress.clear();

  // De-duplicate findings.
  const dedupe = (arr) => {
    const seen = new Set(), out = [];
    for (const x of arr) {
      const k = `${x.file}|${x.name}|${x.version || x.spec}|${x.where}`;
      if (!seen.has(k)) { seen.add(k); out.push(x); }
    }
    return out;
  };
  const C = dedupe(confirmed);
  const N = dedupe(nameMatch);

  const result = {
    tool: 'npm-compromise-scanner',
    version: pkg.version,
    scanDir: ROOT,
    csv: CSV,
    mode: options.skipNodeModules ? 'manifests-only' : 'full',
    affected: {
      names: affected.size,
      pairs: [...affected.values()].reduce((a, s) => a + s.size, 0),
    },
    scanned: {
      packageJson: manifests.filter((m) => m.kind === 'pkg').length,
      packageLock: manifests.filter((m) => m.kind === 'lock').length,
      yarnLock: yarnLocks.length,
      nodeModules: nmScanned,
    },
    parseErrors,
    confirmed: C,
    nameMatches: N,
    nonNpm,
    outcome: C.length ? 'compromised' : 'clean',
  };

  if (options.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return C.length ? EXIT.HITS : EXIT.SUCCESS;
  }

  // --- Human-readable report (stdout) ---------------------------------------
  const out = (s = '') => process.stdout.write(s + '\n');
  out(color.bold(color.cyan(`=== npm-compromise-scanner v${pkg.version} ===`)));
  out(`Scan dir : ${result.scanDir}`);
  out(`CSV      : ${result.csv}`);
  out(`Mode     : ${result.mode === 'full'
    ? 'manifests + lockfiles + installed node_modules'
    : 'manifests + lockfiles only (--skip-node-modules)'}`);
  out();
  out(color.bold('=== SCAN SUMMARY ==='));
  out(`Affected npm packages: ${result.affected.names} names / ${result.affected.pairs} name@version pairs`);
  if (nonNpm.length) out(`Non-npm CSV entries (out of scope): ${nonNpm.length}`);
  out(`Scanned: ${result.scanned.packageJson} package.json, ${result.scanned.packageLock} package-lock.json, ` +
      `${result.scanned.yarnLock} yarn.lock, ${result.scanned.nodeModules} installed node_modules package.json`);
  out(`Parse errors: ${parseErrors.length}`);
  out();

  out(color.bold('=== CONFIRMED: compromised name@version present ==='));
  if (!C.length) out('  ' + color.green('NONE'));
  for (const f of C) {
    out('  ' + color.red(`[HIT] ${f.name}@${f.version}`) + color.dim(`  (${f.where})`));
    out('        ' + color.dim(f.file));
  }
  out();

  out(color.bold('=== DEPENDENCY NAME MATCHES (affected name declared, version is a range) ==='));
  if (!N.length) out('  ' + color.green('NONE'));
  for (const f of N) {
    out('  ' + color.yellow(`[NAME] ${f.name} "${f.spec}"`) + color.dim(`  (${f.where})`));
    out('        ' + color.dim(f.file));
    out('        ' + color.dim(`compromised versions: ${f.affectedVersions.join(', ')}`));
  }

  if (nonNpm.length) {
    out();
    out(color.bold('=== NON-NPM CSV ENTRIES (not scanned - pypi/composer/etc.) ==='));
    nonNpm.forEach((e) => out('  ' + e));
  }
  if (parseErrors.length) {
    out();
    out(color.bold('=== PARSE ERRORS ==='));
    parseErrors.forEach((e) => out('  ' + color.yellow(e)));
  }

  out();
  if (C.length) {
    out(color.red(color.bold(`RESULT: ${C.length} confirmed match(es) - INVESTIGATE.`)));
    return EXIT.HITS;
  }
  out(color.green(color.bold('RESULT: clean - no confirmed compromised package found.')));
  return EXIT.SUCCESS;
}

// --- CLI definition (commander) ---------------------------------------------
const HELP_EXTRA = `
Examples:
  # Scan a project tree against the bundled reference CSV
  $ npm-compromise-scanner ./my-project ./examples/22-packages.csv

  # Faster run - skip the installed node_modules pass
  $ npm-compromise-scanner ./my-project ./incident.csv --skip-node-modules

  # Machine-readable output for automation / CI
  $ npm-compromise-scanner ./my-project ./incident.csv --json

CSV format:
  A header row is required. Columns are matched by name, case-insensitive:
    Ecosystem | Namespace | Name | Version
  Only "Name" and "Version" are required. Non-npm rows are reported but
  not scanned. See examples/22-packages.csv for a real incident CSV.

Exit codes:
  0    clean - no confirmed compromised package found
  1    one or more confirmed compromised name@version present
  2    usage error (bad or missing arguments)
  77   permission denied reading the folder or CSV
  130  interrupted (Ctrl+C)
`;

const program = new Command();
program
  .name('npm-compromise-scanner')
  .description('Scan a directory tree for npm packages compromised in a supply-chain incident, given a CSV of affected packages.')
  .version(pkg.version, '-V, --version', 'output the version number')
  .argument('<scan-dir>', 'directory tree to scan')
  .argument('<affected-csv>', 'CSV of affected packages')
  .option('--skip-node-modules', 'scan only manifests/lockfiles, not installed node_modules')
  .option('--json', 'emit machine-readable JSON to stdout instead of a human report')
  .option('--no-color', 'disable colored output')
  .showHelpAfterError('(run "npm-compromise-scanner --help" for usage)')
  .addHelpText('after', HELP_EXTRA)
  .action((scanDir, affectedCsv, options) => {
    process.exit(runScan(scanDir, affectedCsv, options));
  });

program.exitOverride();
try {
  program.parse(process.argv);
} catch (e) {
  if (e && typeof e.code === 'string' && e.code.startsWith('commander.')) {
    // Help/version exit 0; any usage error exits 2 (MISUSE).
    process.exit(e.exitCode === 0 ? EXIT.SUCCESS : EXIT.MISUSE);
  }
  process.stderr.write(`Unexpected error: ${(e && e.message) || e}\n`);
  process.exit(EXIT.HITS);
}
