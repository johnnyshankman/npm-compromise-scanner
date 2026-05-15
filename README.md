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

Node.js (any reasonably recent version). Zero dependencies — pure stdlib.

## Usage

The tool takes exactly two arguments — the folder to scan and the CSV of
affected packages. Both are required; there are no defaults. It exits
with an error if either is missing.

```bash
node scan.js <folder-to-scan> <affected-packages.csv> [options]
```

Examples:

```bash
# Scan a project tree against the bundled reference CSV
node scan.js /path/to/your/project ./examples/22-packages.csv

# Skip the (slow) installed-node_modules pass
node scan.js /path/to/your/project ./examples/22-packages.csv --skip-node-modules
```

Options:

- `--skip-node-modules` — scan only manifests/lockfiles, not installed `node_modules`
- `--help`, `-h` — show usage

Exit codes (so it can be wired into CI / automation):

- `0` — clean, no confirmed compromised package found
- `1` — one or more confirmed compromised `name@version` present
- `2` — usage / input error (missing folder or missing CSV)

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
