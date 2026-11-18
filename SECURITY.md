# Security policy

## Supported versions

The project is pre-1.0. Security fixes target the latest `v0.x` release and the
`main` branch. Older pre-1.0 versions are not supported.

| Version | Supported |
| --- | --- |
| `v0.x` (latest) | Yes |
| `main` | Yes (development) |
| older `v0.x` | No |

## Reporting a vulnerability

Do not open a public issue, pull request or discussion for a security problem.

Report it privately through GitHub Security Advisories:

https://github.com/edanko/safetech/security/advisories/new

Include:

- the affected version or commit;
- a description of the issue and its impact;
- reproduction steps or a proof of concept;
- any suggested fix or mitigation.

Redact credentials, tokens, private keys, and internal hostnames from the report;
replace them with placeholders.

## What to expect

- Acknowledgement within 3 business days.
- An initial assessment (severity, affected versions, plan) within 7 days.
- A fix or mitigation plan communicated before any public disclosure.
- Credit in the advisory and release notes, if you want it.

Please allow a reasonable window for a fix before publishing details.

## Scope

In scope:

- **Credential and token handling.** Leaks of passwords, client secrets, access
  tokens or refresh tokens; token caching or refresh logic that exposes a token
  or reuses a stale one.
- **TLS verification bypass.** `TLSSkipVerify` enabled without explicit test
  configuration; a custom `HTTPClient` that silently disables verification; any
  path where server certificate validation is skipped.
- **Certificate request and certificate validation.** Accepting a malformed CSR,
  skipping the local CSR self-signature check, or returning a certificate that
  was not verified.
- **Request smuggling and injection.** Header injection through `UserAgent` or
  `EurekaNode`; path injection through certificate IDs, serials or template
  names.
- **Secret exposure in output.** Errors or logs that contain tokens, passwords,
  or PEM private keys.

Out of scope:

- Vulnerabilities in the SafeTech CA product itself, its gateway, or Keycloak.
  Report those to the vendor.
- Findings that require modifying the client, disabling certificate validation,
  or running it outside its documented configuration.
- Denial of service caused by resource exhaustion on the CA side.

## Secrets in this repository

- The client never logs the password or the access token.
- Logs and errors must not contain tokens, passwords, or PEM private keys. When
  adding diagnostics, redact `Authorization` headers and request bodies.
- Never commit credentials, real CSRs, private keys, internal hostnames or
  internal template names. Use environment variables and the placeholders in
  `README.md`.
