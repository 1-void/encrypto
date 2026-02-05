# Security Policy

This project is experimental and unaudited. Please treat it accordingly.

## Reporting a Vulnerability
- Preferred: use GitHub Security Advisories
- For complex or coordinated disclosures: email root@1-void.com (obviously always PGP your messages until we have this running)

Please do not open public issues for security problems.

## OpenSSL Policy
We target OpenSSL 3.5.x with PQC support. The bootstrap script pins tags and supports optional commit verification via `OPENSSL_COMMIT` (and `PQC_VERIFY=1` to enforce). When OpenSSL, liboqs, or oqs-provider ship security updates, we will bump the pinned tags promptly and document the change in the repo.

If you discover a vulnerability related to OpenSSL, providers, or our build scripts, please report it via the channels above.

## Provider Configuration
PQC support depends on OpenSSL providers being available and loaded. The `doctor` command reports runtime algorithm support, and CI enforces PQC availability. If you run in a restricted environment (e.g., FIPS-only), expect PQC to be unavailable.

## Response Expectations
We will acknowledge reports as quickly as possible and work with you on a fix.
