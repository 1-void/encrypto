# QPGP PQC Profile (Draft Alignment)

Target spec: `draft-ietf-openpgp-pqc-17` (IETF OpenPGP PQC draft).

## Goals
- OpenPGP-compatible CLI with PQC by default.
- PQC-only build with no classical fallback.
- Fail-closed when PQC is required but unavailable.
- No silent downgrade to classical cryptography.

## Algorithms (Draft Profile)
We align with the draft’s composite (hybrid) algorithms and IDs:
- Signatures (composite):
  - ML-DSA-65 + Ed25519 (MUST)
  - ML-DSA-87 + Ed448 (SHOULD)
- Signatures (standalone):
  - SLH-DSA family (MAY)
- Encryption (composite KEM):
  - ML-KEM-768 + X25519 (MUST)
  - ML-KEM-1024 + X448 (SHOULD)

## Key Versions
- PQC operations are v6 keys by default (RFC 9580 profile).
- The draft allows ML-KEM-768+X25519 (algorithm 35) in v4 encryption subkeys; we accept that *key version* exception for interop, but still enforce PQC policy at the artifact level.
- PQC signatures require v6 signatures; non-v6 PQC signatures are rejected.

## Policy
- `PQC required` is the default.
- PQC-only build: non-required policies are rejected and non-PQC artifacts are refused.
- Certificate acceptance: all key material in a cert must be PQC-capable (no mixed classical primary keys with PQC subkeys).
- When required, all outputs are validated and must contain only PQC algorithms:
  - Encryption: require SEIP v2 (AEAD) using AES-256 + OCB; every PKESK must use PQC KEM algorithms.
    - Additionally: if SEIP v2 is present, PKESK v3 is rejected (spec forbids mixing PKESK v3 cipher IDs with SEIP v2).
  - Signatures: signature algorithms must be PQC; hashes must be >= 256-bit.
- Decrypt/verify also reject non-PQC artifacts when policy is required.

## Revoked Keys
- By default, QPGP will not use revoked keys for encryption/signing or decryption.
- For archival recovery, decryption supports an explicit opt-in: `qpgp decrypt --allow-revoked-keys`.

## Key Generation Levels
- `baseline`: ML-DSA-65 + Ed25519, ML-KEM-768 + X25519.
- `high`: ML-DSA-87 + Ed448, ML-KEM-1024 + X448 (if supported, otherwise fallback to baseline).

## Backend Notes
- `native` backend uses Sequoia OpenPGP with OpenSSL 3.5+ PQC support.
- `gpg` backend is disabled in PQC-only builds.

## Non-goals (for now)
- Full GUI or Kleopatra parity.
- Classic/PQC compatibility modes or dual artifacts.
- Broad interop guarantees beyond the draft profile.
