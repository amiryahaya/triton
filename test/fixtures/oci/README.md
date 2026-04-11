# OCI Image Test Fixtures

Committed rootfs used by `pkg/scanner/oci_image_test.go`.

## minimal-rootfs/

Pre-extracted rootfs layout returned by `fakeFetcher` in unit tests.

- `etc/ssl/certs/test-ca.pem` — self-signed RSA-2048 cert, 10-year validity.
  Exists to give the `certificates` module something to find.
- `usr/lib/libssl.so.3` — empty file. Matches `library` module's filename-based
  detection without needing real ELF bytes.
- `usr/bin/curl` — empty file. Matches `binary` module's filename allowlist.

## Regeneration

The test CA is committed, not generated at test time, to keep tests
deterministic and avoid build-time crypto. To regenerate (e.g. if validity
expires), see the openssl command in Task 9 Step 1 of the Wave 0 plan:
`docs/plans/2026-04-12-wave-0-oci-infra-plan.md`.
