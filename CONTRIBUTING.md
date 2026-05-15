# Contributing

Thanks for your interest in improving `npm-compromise-scanner`.

## Workflow

The `main` branch is protected. All changes land through a pull request:

1. Fork the repository and create a branch off `main`.
2. Make your change.
3. Run the test suite locally:
   ```bash
   npm install
   npm test
   ```
4. Open a pull request. CI runs the test suite on Linux, macOS, and
   Windows; all checks must pass before a maintainer can merge.

Direct pushes to `main` are not accepted — fork-and-PR only.

## Guidelines

- **Keep it dependency-light.** This is a supply-chain security tool;
  every dependency is attack surface. `commander` is the only runtime
  dependency — please do not add more without a strong reason.
- **Add a test** for any behavior change in `test/cli.test.js`.
- Match the existing code style (plain CommonJS, no build step).
- The scanner must stay **read-only** — it must never write to, install
  into, or execute a scanned project.

## Reporting bugs

Open an issue with the command you ran, the expected result, and the
actual result. For security issues, see [SECURITY.md](SECURITY.md)
instead — do not file them publicly.
