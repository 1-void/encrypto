# encrypto

Plan: build a simple, OpenPGP-compatible CLI with post-quantum keys and E2EE, then expand from there.

Spec target: `draft-ietf-openpgp-pqc-17`.

We follow the draft’s post-quantum OpenPGP profile:
- Composite (hybrid) algorithms for encryption and signatures (ML-KEM + X25519, ML-DSA + Ed25519/Ed448).
- v6 key profile for PQC operations.
- PQC required by default; outputs are validated to avoid classical fallbacks.
- PQC-only build: classical modes and the gpg backend are disabled.

See `SPEC.md` for the implementation profile and policy details.

Nobody wants to give enough time to build a post quantum pgp. so i did.

## Status

Community preview. PQC-only, unapologetically strict, and still evolving.
Not yet audited. If you want to help harden it, you’re welcome.

## Run

Build and run the CLI:
```bash
cargo run -p encrypto-cli -- --help
```

Generate a high-assurance PQC key:
```bash
cargo run -p encrypto-cli -- keygen "Alice <alice@example.com>" --pqc-level high
```

Default `--pqc-level` is `high` for stronger parameters. Use `--pqc-level baseline` if you need smaller keys/signatures.

Generate a PQC key with a passphrase (native backend):
```bash
cargo run -p encrypto-cli -- --passphrase-file ./pass.txt keygen "Alice <alice@example.com>"
```

Keygen requires a passphrase by default (native). Use `--no-passphrase` to override:
```bash
cargo run -p encrypto-cli -- --no-passphrase keygen "Alice <alice@example.com>"
```

Post-quantum mode (builds OpenSSL locally, then runs with PQC enabled):
```bash
./scripts/bootstrap-pqc.sh
source scripts/pqc-env.sh
cargo run -p encrypto-cli -- info
```

Optional source verification (recommended for reproducibility):
```bash
export PQC_VERIFY=1
export OPENSSL_COMMIT=<expected-commit-sha>
export LIBOQS_COMMIT=<expected-commit-sha>
export OQSPROVIDER_COMMIT=<expected-commit-sha>
./scripts/bootstrap-pqc.sh
```

Basics:
```bash
cargo run -p encrypto-cli -- encrypt -r <KEY_ID> message.txt -o msg.pgp
cargo run -p encrypto-cli -- decrypt -o message.txt msg.pgp
cargo run -p encrypto-cli -- sign -u <KEY_ID> message.txt -o message.sig
cargo run -p encrypto-cli -- verify --signer <FULL_FINGERPRINT> message.sig message.txt
cargo run -p encrypto-cli -- sign -u <KEY_ID> --clearsign message.txt -o message.asc
cargo run -p encrypto-cli -- verify --signer <FULL_FINGERPRINT> --clearsigned message.asc
cargo run -p encrypto-cli -- export <KEY_ID> --armor -o key.asc
```

Note: sensitive operations require a full fingerprint (40 or 64 hex characters). Verification requires `--signer` to pin the expected signer. Use `list-keys` to find the exact fingerprint.

Passphrase note: prefer `--passphrase-file` to avoid exposing secrets in process listings.
Large files: inputs are limited to 64 MiB by default. Override with `ENCRYPTO_MAX_INPUT_BYTES`.

Key lifecycle:
```bash
cargo run -p encrypto-cli -- revoke <KEY_ID> --reason key-superseded --armor -o revoked.asc
cargo run -p encrypto-cli -- rotate <KEY_ID>
```

Diagnostics:
```bash
cargo run -p encrypto-cli -- doctor
```

If you need oqs-provider explicitly:
```bash
PQC_WITH_OQS=1 ./scripts/bootstrap-pqc.sh
```

Draft vectors (optional):
```bash
./scripts/fetch-draft-vectors.sh
cargo test -p encrypto-pgp --test draft_vectors
```

## Contributing

Keep it simple.

If you change crypto behavior, include a quick end-to-end check:
```bash
cargo run -p encrypto-cli -- info
```

Prefer small commits with clear messages.

AI is welcome. If you use AI, make sure your edits are supervised and carefully audited before you open a PR.

See `CONTRIBUTING.md` for the full workflow and `SECURITY.md` for vulnerability reporting.

Note: PQC tests will skip locally if PQC support is missing; CI enforces PQC.

## Security

Please do not open public issues for security vulnerabilities. Use GitHub Security Advisories or email `root@1-void.com`.

## License

MIT. See `LICENSE`.
