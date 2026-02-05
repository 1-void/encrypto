# encrypto

Plan: build a simple, OpenPGP-compatible CLI with post-quantum keys and E2EE, then expand from there.

Spec target: `draft-ietf-openpgp-pqc-17`.

We follow the draft’s post-quantum OpenPGP profile:
- Composite (hybrid) algorithms for encryption and signatures (ML-KEM + X25519, ML-DSA + Ed25519/Ed448).
- v6 key profile for PQC operations.
- PQC required by default; outputs are validated to avoid classical fallbacks.
- `--compat` explicitly allows mixed PQC + classical recipients with a warning.

See `SPEC.md` for the implementation profile and policy details.

Nobody wants to give enough time to build a post quantum pgp. so i did.

## Run

Build and run the CLI:
```bash
cargo run -p encrypto-cli -- --help
```

Generate a high-assurance PQC key:
```bash
cargo run -p encrypto-cli -- keygen "Alice <alice@example.com>" --pqc-level high
```

Post-quantum mode (builds OpenSSL locally, then runs with PQC enabled):
```bash
./scripts/bootstrap-pqc.sh
source scripts/pqc-env.sh
cargo run -p encrypto-cli -- --native info
```

GPG-style basics:
```bash
cargo run -p encrypto-cli -- --native encrypt -r <KEY_ID> message.txt -o msg.pgp
cargo run -p encrypto-cli -- --native decrypt -o message.txt msg.pgp
cargo run -p encrypto-cli -- --native sign -u <KEY_ID> message.txt -o message.sig
cargo run -p encrypto-cli -- --native verify message.sig message.txt
```

Disable PQC (dangerous, for compatibility only):
```bash
cargo run -p encrypto-cli -- --gpg --pqc-disabled list-keys
```

Allow mixed PQC + classical recipients (dangerous; reduces PQ confidentiality):
```bash
cargo run -p encrypto-cli -- --native --compat encrypt -r <KEY_ID> message.txt -o msg.pgp
```

If you need oqs-provider explicitly:
```bash
PQC_WITH_OQS=1 ./scripts/bootstrap-pqc.sh
```

## Contributing

Keep it simple.

If you change crypto behavior, include a quick end-to-end check:
```bash
cargo run -p encrypto-cli -- --backend native --pqc required info
```

Prefer small commits with clear messages.

AI is welcome. If you use AI, make sure your edits are supervised and carefully audited before you open a PR.
