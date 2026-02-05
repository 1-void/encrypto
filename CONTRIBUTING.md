# Contributing

Thanks for helping build a strict, PQC-only OpenPGP tool.
This project is intentionally conservative and security-focused.

## Ground Rules
- PQC-only is non-negotiable. Do not add classical or mixed-mode paths.
- Keep changes small and well-tested.
- If you change crypto behavior, update `SPEC.md` and tests.

## Quick Start
- Build: `cargo build`
- Tests (recommended): `cargo test -p encrypto-pgp --tests`
- PQC runtime: `./scripts/bootstrap-pqc.sh` then `source scripts/pqc-env.sh`
- CLI help: `cargo run -p encrypto-cli -- --help`

## Coding Style
- Run `cargo fmt` if you touch Rust files.
- Keep error messages clear and actionable.

## Submitting Changes
- Open an issue or discuss in an existing one first for non-trivial changes.
- Use clear commit messages and describe the security impact.
- Add tests where behavior changes.

## PQC Test Notes
Local tests will skip PQC-heavy cases if PQC support is missing. CI requires PQC,
so run the bootstrap script to avoid surprises:
- `./scripts/bootstrap-pqc.sh`
- `source scripts/pqc-env.sh`

## Security
Please do not file security issues publicly. See `SECURITY.md` for reporting.
