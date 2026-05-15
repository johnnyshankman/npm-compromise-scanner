# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting instead:
the repository's **Security** tab → **Report a vulnerability**.

Expect an initial response within a few days.

## Scope

`npm-compromise-scanner` is a **read-only** tool. It reads `package.json`,
`package-lock.json`, `yarn.lock`, and `node_modules/` manifests, and never
modifies, installs, downloads, or executes project code.

Reports are especially welcome for anything that could cause the scanner to:

- write to or delete files in a scanned tree,
- execute code from a scanned project,
- make network requests, or
- leak the contents of scanned files anywhere other than its own report.

## Supported versions

The latest release on the `main` branch is supported. There are no
backported fixes for older versions.
