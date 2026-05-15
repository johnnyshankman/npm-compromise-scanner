# npm-compromise-scanner

Scan a directory tree for npm packages compromised in a supply-chain
incident, given a CSV of affected packages.

When a wave of malicious npm package versions is published (the kind of
incident where a security feed drops a CSV of "affected packages"), this
tool tells you whether any of them landed on your machine — declared,
locked, or actually installed.

## Background

This tool was inspired by the **"Mini" Shai-Hulud npm supply-chain
attack** — a wave of compromised package versions (including many
`@tanstack/*` packages) published to the npm registry.

The bundled reference list,
[`examples/22-packages.csv`](examples/22-packages.csv), is the
compromised-package CSV published by Socket:

<https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack#All-Compromised-Packages>

For a future incident, point the scanner at a fresh CSV exported from the
relevant advisory — no code changes needed.

## Why

Restricting a check to `package-lock.json` alone gives a false sense of
security: projects that use Yarn have no `package-lock.json`, and a
lockfile can drift from what is actually installed. This scanner checks
**four** sources so the answer reflects reality:

| Source | What it tells you |
|---|---|
| `package.json` | Dependencies you declared (may be version ranges) |
| `package-lock.json` | npm-resolved exact versions (lockfileVersion 1/2/3) |
| `yarn.lock` | Yarn-resolved exact versions (classic v1 + berry v2+) |
| `node_modules/` | Packages **actually installed on disk** — authoritative |

## Requirements

Node.js **>= 20**.

## Setup

One runtime dependency — [`commander`](https://github.com/tj/commander.js),
for argument parsing. Install it once:

```bash
npm install
```

Optionally, expose the `npm-compromise-scanner` command on your `PATH`
(also what the shell completions below hook into):

```bash
npm link
```

## Usage

The tool takes exactly two arguments — the folder to scan and the CSV of
affected packages. Both are required; there are no defaults.

```bash
node scan.js <folder-to-scan> <affected-packages.csv> [options]

# or, after `npm link`:
npm-compromise-scanner <folder-to-scan> <affected-packages.csv> [options]
```

Examples:

```bash
# Scan a project tree against the bundled reference CSV
node scan.js /path/to/your/project ./examples/22-packages.csv

# Faster run — skip the installed-node_modules pass
node scan.js /path/to/your/project ./examples/22-packages.csv --skip-node-modules

# Machine-readable output for automation / CI
node scan.js /path/to/your/project ./examples/22-packages.csv --json
```

Options:

- `--skip-node-modules` — scan only manifests/lockfiles, not installed `node_modules`
- `--json` — emit machine-readable JSON to stdout instead of the human report
- `--no-color` — disable colored output (color is auto-disabled when stdout
  is not a TTY, or when `NO_COLOR` is set)
- `-V, --version` — print the version
- `-h, --help` — show usage

The human-readable report is written to **stdout**; progress and
diagnostics go to **stderr**, so `… > report.txt` captures just the report
and `… | grep HIT` works cleanly.

Exit codes (so it can be wired into CI / automation):

- `0` — clean, no confirmed compromised package found
- `1` — one or more confirmed compromised `name@version` present
- `2` — usage error (bad or missing arguments)
- `77` — permission denied reading the folder or CSV
- `130` — interrupted (Ctrl+C)

## Shell completions

Completion scripts for the `npm-compromise-scanner` command live in
[`completions/`](completions/). Each file's header has full install
instructions; the short version:

```bash
# bash — source it from ~/.bashrc
source completions/npm-compromise-scanner.bash

# zsh — drop it on your $fpath, then recompinit
cp completions/_npm-compromise-scanner ~/.zsh/completions/

# fish
cp completions/npm-compromise-scanner.fish ~/.config/fish/completions/
```

## Testing

```bash
npm test
```

Runs the built-in Node.js test runner (`node --test`) against
[`test/cli.test.js`](test/cli.test.js) — version/help output, argument
validation, exit codes, clean vs. compromised detection, and JSON mode.
The fixtures under `test/fixtures/` are static; the "compromised" fixture
deliberately names a known-bad package version (with no `package.json`
beside it, so it can never be installed).

## CSV format

A header row is required. Columns are matched by name, case-insensitive,
so order does not matter and extra columns are ignored. Recognised columns:

| Column | Aliases | Required |
|---|---|---|
| `Ecosystem` | `Type` | no (rows assumed `npm` if absent) |
| `Namespace` | `Scope` | no |
| `Name` | `Package` | **yes** |
| `Version` | `Affected Version` | **yes** |

Notes:

- Only rows whose `Ecosystem` is `npm` (or absent) are scanned. Other
  ecosystems (`pypi`, `composer`, …) are listed in the report as
  out-of-scope but not matched.
- The `Namespace` value may include the leading `@` or not — both work.
- If `Name` already contains a scope (`@scope/pkg`), it is used as-is.

The bundled [`examples/22-packages.csv`](examples/22-packages.csv) is a
real incident CSV in exactly this format — use it as a template.

## Reading the output

- **CONFIRMED** — a compromised `name@version` is present (resolved in a
  lockfile, installed in `node_modules`, or pinned exactly in a
  `package.json`). These are real hits — investigate immediately.
- **DEPENDENCY NAME MATCHES** — a `package.json` declares a dependency
  whose *name* is on the affected list, but with a version *range*. Not
  necessarily compromised; cross-check against the resolved version in
  the lockfile / `node_modules` (the scanner does this automatically when
  those are present).

With `--json`, the same information is emitted as a structured object
(`outcome`, `confirmed[]`, `nameMatches[]`, `scanned`, `parseErrors`, …)
for programmatic use.

## Getting a CSV for a new incident

When a future incident happens, export the affected package list as a CSV
with at least `Name` and `Version` columns (plus `Ecosystem`/`Namespace`
if available) and point the scanner at it. Sources that publish such
lists include security advisory feeds, Socket, Snyk, the GitHub Advisory
Database, and npm security advisories.

## Limitations

- npm only. `pypi` / `composer` / other ecosystems are reported but not
  matched — those need a separate check (`requirements.txt`,
  `poetry.lock`, `composer.json`, etc.).
- Matching is exact `name@version`. It does not evaluate semver ranges in
  `package.json`; that is what the lockfile / `node_modules` passes are
  for.

## Contributing & security

Contributions go through pull requests against the protected `main`
branch — see [CONTRIBUTING.md](CONTRIBUTING.md). CI runs the test suite on
Linux, macOS, and Windows; all checks must pass before merge.

To report a security issue, see [SECURITY.md](SECURITY.md) — please do not
file security problems as public issues.

This project is [MIT licensed](LICENSE).
