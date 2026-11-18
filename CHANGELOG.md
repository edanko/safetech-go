# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet. Changes for the next release are added here.

## [0.1.0] - 2026-11-18

First public release.

### Added

- `Client` for the SafeTech CA `ca-core` REST API: certificate issuance from a
  PEM-encoded PKCS#10 CSR against a named CA template, and certificate
  revocation.
- `New` constructor that validates the configuration and performs no network
  I/O until the first operation.
- `IssuedCertificate` carrying `ID`, serial number, PEM, template name, status and
  validity window, with `ParsePEM` returning an `*x509.Certificate`.
- Context-first API: `CreateCertificate` and `RevokeCertificate` take a
  `context.Context` as their first argument.
- `ListTemplates`, returning the certificate templates configured in the CA with
  their protocol, validity, key-usage and ST_CA enrollment settings.
- `Config.APIBaseURL` to address `ca-core` directly instead of through the
  gateway.
- `Config.Retry` with a `RetryPolicy` that retries transient failures on
  idempotent requests and honours `Retry-After`.
- `RevokeCertificateWithOptions` and `RevokeOptions.AllowAlreadyRevoked`, for
  idempotent revocation in reconciliation loops.
- Local CSR validation before a request is sent: PEM decode, parse, and
  self-signature check.
- RFC 5280 revocation reasons (`RevokeReason`) selected through
  `Config.RevokeReason`.
- Keycloak authentication with automatic endpoint discovery
  (`/api/ui-config`), access-token caching, refresh-token renewal, and a
  password-grant fallback.
- Typed errors: `ErrInvalidCSR`, `ErrCertificateNotFound` and
  `ErrCertificateRevoked` for `errors.Is`; `HTTPError` and `APIError` for
  `errors.As`.
- `Version` variable (default `dev`), settable with
  `-ldflags "-X github.com/edanko/safetech.Version=v1.2.3"`.
- Vendor documentation references in the README: the SafeTech CA API article,
  how to enable the `ca-core` Swagger UI for the full endpoint reference, and
  the note that `Config.BaseURL` expects the gateway endpoint.

### Changed

- The module targets Go 1.27 and uses the standard-library `uuid` package
  (`UUID`, `NewV4`/`NewV7`, `Parse`, `Max`, comparison and text marshalling).
  It has no third-party dependencies.
- Concurrent requests no longer serialise on the token cache: exactly one
  goroutine performs a token request while the others wait for its outcome, and
  cache hits do not touch the network path.
- Requests that issue or revoke certificates are never retried, because the CA
  offers no idempotency for them; only token, discovery and GET requests are.
- The public API is the concrete `*Client`; no interface is exported, so
  callers declare the narrow interface they need.
- `*Client` is safe for concurrent use; the access token is shared behind a
  mutex.
- The integration test runs only behind the `integration` build tag and reads
  its configuration from `STCA_BASE_URL`, `STCA_REALM_URL`, `STCA_USERNAME` and
  `STCA_PASSWORD`.

### Fixed

- A `Retry-After` value large enough to overflow `time.Duration` produced a
  negative delay; it is now clamped to 24 hours. Found by `FuzzParseRetryAfter`,
  whose input is kept as a regression seed in `testdata/fuzz`.

### Security

- Removed credentials, internal hostnames and internal template names that were
  present in the working tree before the first public release; the exposed
  credentials must be rotated.
- The client never logs the password or the access token.
- `TLSSkipVerify` is documented as test-only and must never be enabled in
  production.
