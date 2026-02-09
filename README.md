# QPGP

Hobby / experimental project.

Explanation notes:

Plan: build a simple, OpenPGP-compatible CLI with post-quantum keys and E2EE, then expand from there.

Spec target: `draft-ietf-openpgp-pqc-17`.

We follow the draft’s post-quantum OpenPGP profile:
- Composite (hybrid) algorithms for encryption and signatures (ML-KEM + X25519, ML-DSA + Ed25519/Ed448).
- v6 key profile for PQC operations.
- PQC required by default; outputs are validated to avoid classical fallbacks.
- Certificates are PQC-only: mixed classical primary keys with PQC subkeys are rejected on import/load.
- PQC-only build: classical modes and the gpg backend are disabled.

See `SPEC.md` for the implementation profile and policy details.
