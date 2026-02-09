# Security Audit Checklist (PQC-Only)

This file tracks remediation work items from a security review focused on:
- downgrade resistance
- correctness vs `draft-ietf-openpgp-pqc-17`
- trust boundaries (filesystem + OpenSSL provider loading)
- "dangerous convenience" failure modes

## Status

- [x] CRITICAL: Cleartext signature PQC enforcement bound to verified signature packets (no armor substring gate).
- [x] CRITICAL: Cert loading merges public updates into secret certs (no silent overwrite).
- [x] HIGH: Filesystem trust invariants enforced for `QPGP_HOME` and key dirs (ownership/perms, reject symlinks); relative-home bypass only via explicit insecure flag.
- [x] HIGH: CI pins OpenSSL revision and requires it (`PQC_VERIFY=1` + `OPENSSL_COMMIT`).
- [x] HIGH: CI exercises optional OQS provider path with pinned `liboqs`/`oqs-provider` revisions.
- [x] HIGH: CI pins GitHub Actions by commit SHA (no floating tags).
- [x] MEDIUM: Encryption policy tightened: require SEIPDv2 + AES-256 + OCB; PKESK v3 allowed only for the draft's ML-KEM-768+X25519 v4 interop exception.
- [x] MEDIUM: "PQC-only cert" check covers all keys (including expired/revoked).
- [x] MEDIUM: Import signature rules require PQC for self-signatures/bindings; allow non-PQC third-party certifications (treated as non-PQ-secure metadata).
- [x] MEDIUM: CLI gates `--passphrase` behind an explicit unsafe flag.
- [x] LOW: SPEC high-suite fallback mismatch fixed (High falls back to Baseline if unsupported).
- [x] LOW: `write_atomic` fsyncs directory after rename (durability hardening).
- [x] LOW: Keystore loader ignores non-`.pgp` files (prevents junk files from bricking key loading).

## Remaining (Nice To Have / Future Work)

- [ ] Supply chain: verify upstream provenance (signed tags/commits) for OpenSSL / liboqs / oqs-provider.
- [ ] Supply chain: support tarball+SHA256 pinning as an alternative to git clones.
- [ ] SBOM/provenance: generate and attach SBOM artifacts in CI.
- [ ] UX: add interactive passphrase prompt / pinentry integration (keep argv passphrases discouraged).
- [ ] Docs: explicitly document metadata leakage (recipient identifiers) and "hidden recipients" status.
