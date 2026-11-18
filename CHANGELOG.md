# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet. Changes for the next release are added here.

## [0.1.0] - 2026-11-18

First public release: a client for the SafeTech CA `ca-core` REST API, requiring
Go 1.27 and depending only on the standard library.

### Added

- Certificate issuance from a PEM-encoded PKCS#10 CSR against a named CA
  template, with local validation of the CSR (PEM decode, parse, self-signature
  check) and `ErrInvalidCSR` for requests the CA would reject.
- Certificate revocation by the request ID returned at issuance, with RFC 5280
  reasons through `Config.RevokeReason`, idempotent revocation through
  `RevokeOptions.AllowAlreadyRevoked`, and `ErrCertificateRevoked` /
  `ErrCertificateNotFound` for the recoverable cases.
- `GetCertificate`, which reads a certificate back by serial number — the way
  back to one whose PEM was not persisted after issuance — reporting an unknown
  serial as `ErrCertificateNotFound`.
- `ListTemplates`, returning the configured templates with their protocol,
  validity, key-usage and ST_CA enrollment settings.
- `IssuedCertificate`, carrying the request ID, serial number, PEM, template
  name and ID, status and validity window, together with the chain material the
  CA returns: `Chain`, `FullChain`, `Root`, `PKCS7` and `DNHash`, all `nil` when
  the CA omits them. `ParsePEM` decodes the leaf into an `*x509.Certificate`.
- Keycloak authentication with `/api/ui-config` discovery, a cached access
  token, refresh-token renewal and a password-grant fallback.
- `Config.RootCAs` and `RootCAsFromPEM` for trusting a private CA, which every
  SafeTech CA installation needs: it signs its own gateway and Keycloak
  endpoints with its own root.
- `Config.APIBaseURL` to address `ca-core` directly instead of through the
  gateway, and `Config.Retry` with a `RetryPolicy` that retries transient
  failures on idempotent requests only and honours `Retry-After`.
- A context-first API: every operation takes a `context.Context`, and `*Client`
  is safe for concurrent use with a single in-flight token request shared by
  waiting callers.
- Typed errors: sentinels for `errors.Is` and `*HTTPError` / `*APIError` for
  `errors.As`, so callers never match on error strings.
- The version reported in the `User-Agent` header is detected from the build
  information of the importing program, so consumers report the version they
  built against without changing their build. `safetech.Version` overrides it,
  and `dev` is the fallback for test binaries and local `replace` directives.

### Security

- The repository carries no credentials, internal hostnames or internal
  template names; documentation and examples use placeholder URLs and template
  names. The password that was present in the working tree before the first
  release must still be rotated.
- The client never logs the password or the access token.
- `TLSSkipVerify` is documented as test-only, cannot be combined with
  `Config.RootCAs`, and is never enabled by default; verification failures are
  reported immediately rather than retried.
