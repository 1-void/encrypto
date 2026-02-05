# encrypto

Plan: build a simple, OpenPGP-compatible CLI with post-quantum keys and E2EE, then expand from there.

Nobody wants to give enough time to build a post quantum pgp. so i did.

## Run

Build and run the CLI:
```bash
cargo run -p encrypto-cli -- --help
```

Post-quantum mode (builds OpenSSL + oqs-provider locally, then runs with PQC enabled):
```bash
./scripts/bootstrap-pqc.sh
source scripts/pqc-env.sh
cargo run -p encrypto-cli -- --backend native --pqc required info
```

## Contributing

Keep it simple.

If you change crypto behavior, include a quick end-to-end check:
```bash
cargo run -p encrypto-cli -- --backend native --pqc required info
```

Prefer small commits with clear messages.

AI is welcome. If you use AI, make sure your edits are supervised and carefully audited before you open a PR.
