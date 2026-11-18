# safetech

Go client for the SafeTech CA certificate authority (`ca-core` REST API):
issue X.509 user certificates from a CSR and revoke them.

Vendor documentation (Russian):
[SafeTech CA API — Swagger and request examples](https://docs.safetechlab.ru/share/e0dabuov2p/p/swagger-i-primery-zaprosov-v-api-safe-tech-ca-zPrNWFhF5l).

[![CI](https://img.shields.io/github/actions/workflow/status/edanko/safetech/test.yml?branch=main)](https://github.com/edanko/safetech/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/edanko/safetech.svg)](https://pkg.go.dev/github.com/edanko/safetech)
[![Go Version](https://img.shields.io/github/go-mod/go-version/edanko/safetech)](https://go.dev/)
[![License: MIT](https://img.shields.io/github/license/edanko/safetech)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/edanko/safetech)](https://goreportcard.com/report/github.com/edanko/safetech)

## Features

- Issues certificates from PEM-encoded PKCS#10 CSRs against a named CA template.
- Validates the CSR locally (PEM decode, parse, self-signature check) before any
  request is sent; invalid requests return `ErrInvalidCSR`.
- Lists the CA certificate templates, including the ST_CA enrollment settings that
  constrain a request.
- Revokes certificates by the ID returned at issuance, with RFC 5280 revocation reasons.
- Authenticates against Keycloak with cached, automatically refreshed access tokens.
- Takes a `context.Context` on every operation, so cancellation and deadlines propagate.
- Retries transient failures (429/5xx, network errors) on idempotent requests
  only, honouring `Retry-After`; never on issuance or revocation.
- Addresses either the CA gateway or `ca-core` directly.
- Revokes idempotently when a reconciliation loop needs that.
- Returns sentinel errors for `errors.Is` and typed `*HTTPError` / `*APIError` values for `errors.As`.
- Is safe for concurrent use.
- Depends only on the standard library.

## Requirements

- Go 1.27 or newer. The client uses the `uuid` package added to the standard
  library in Go 1.27, which is why the module has no third-party dependencies.

## Install

```sh
go get github.com/edanko/safetech
```

## Quick start

The program below reads a PEM-encoded CSR, issues a certificate from the
`MY_TEMPLATE` CA template, prints the serial number and validity window, then
revokes the certificate.

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/edanko/safetech"
)

func main() {
	ctx := context.Background()

	csrPEM, err := os.ReadFile("device.csr")
	if err != nil {
		log.Fatalf("read CSR: %v", err)
	}

	client, err := safetech.New(safetech.Config{
		BaseURL:  "https://ca.example.com:7443",
		Username: os.Getenv("STCA_USERNAME"),
		Password: os.Getenv("STCA_PASSWORD"),
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	cert, err := client.CreateCertificate(ctx, csrPEM, "MY_TEMPLATE")
	if err != nil {
		log.Fatalf("issue certificate: %v", err)
	}
	fmt.Printf("serial: %s\n", cert.SerialNumber)
	fmt.Printf("status: %s\n", cert.Status)
	fmt.Printf("valid:  %s .. %s\n",
		cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))

	if err := client.RevokeCertificate(ctx, cert.ID); err != nil {
		switch {
		case errors.Is(err, safetech.ErrCertificateRevoked):
			log.Printf("certificate was already revoked: %v", err)
		case errors.Is(err, safetech.ErrCertificateNotFound):
			log.Printf("certificate not found: %v", err)
		default:
			var httpErr *safetech.HTTPError
			if errors.As(err, &httpErr) {
				log.Fatalf("gateway returned HTTP %d: %s", httpErr.StatusCode, httpErr.Body)
			}
			log.Fatalf("revoke certificate: %v", err)
		}
	}
}
```

`UserCertificate` carries `ID` (pass it to `RevokeCertificate` later),
`SerialNumber`, `PEM`, `TemplateName`, `Status`, `NotBefore` and `NotAfter`.
Call `ParsePEM` to decode the issued certificate into an `*x509.Certificate`.

`New` validates the configuration and performs no network I/O; authentication
happens lazily on the first operation. The client holds no resources that need
to be closed. More recipes are in [docs/EXAMPLES.md](docs/EXAMPLES.md).

## Configuration

`safetech.Config`:

| Field | Default | Meaning |
| --- | --- | --- |
| `BaseURL` | required | Gateway base URL, for example `https://ca.example.com:7443`. The `ca-core/api/v1` path prefix is appended automatically. |
| `AuthURL` | empty (discover) | Keycloak realm URL, for example `https://keycloak.example.com/realms/ca`. When set, `/api/ui-config` discovery is skipped. |
| `ClientID` | discovered (`ca-ui`) | OIDC client used for authentication. The vendor examples use the confidential `ca-gateway` client; set it explicitly when your realm is provisioned that way. |
| `ClientSecret` | empty | Client secret for confidential clients such as `ca-gateway`. Leave empty for the public `ca-ui` client. |
| `Username` | required | Account for the password grant. |
| `Password` | required | Password for the password grant. |
| `EurekaNode` | `ST CA Root` | CA node identity, sent as the `x-eureka-node` header. |
| `RevokeReason` | `RevokeReasonUnspecified` | Revocation reason used by `RevokeCertificate`. |
| `TLSSkipVerify` | `false` | Disables server certificate verification. Test environments only; see [Security notes](#security-notes). |
| `HTTPClient` | `nil` (internal default) | Optional custom `*http.Client`. When `TLSSkipVerify` is set, the custom transport must be an `*http.Transport`. |
| `UserAgent` | `safetech/<Version>` | `User-Agent` header sent to the API. |
| `Retry` | 3 attempts, 200ms backoff, 5s cap | Retry policy for idempotent requests. See [Retries](#retries). |
| `APIBaseURL` | empty | Full base URL of the `ca-core` API, for example `http://ca-core.example.com:8081/api/v1`. Set it to bypass the gateway; `BaseURL` is then ignored and `AuthURL` becomes required. |

## Authentication

The gateway protects the `ca-core` API with Keycloak. The client uses the
Resource Owner Password Credentials grant against the `ca-ui` public OIDC
client, the same client the SafeTech CA web UI uses.

- **Discovery.** Unless `AuthURL` is set, the client calls
  `{BaseURL}/api/ui-config`, which advertises the Keycloak URL, realm and client
  ID. Set `AuthURL` to skip that call, for example when the gateway does not
  expose `ui-config`.
- **Token lifecycle.** The access token is obtained lazily, cached, and
  refreshed with the refresh-token grant before it expires. If the refresh
  fails, the client falls back to the password grant.
- **Clients.** The vendor documentation authenticates with the confidential
  `ca-gateway` client and a client secret, which is also what `CA CLI` prompts
  for (realm URL, client ID, client secret, administrator credentials). The web
  UI uses the public `ca-ui` client, which is what discovery returns when
  `ClientID` is empty. Set `ClientID` and `ClientSecret` explicitly when your
  installation is provisioned around the confidential client.
- Credentials are taken from the configuration only. The client never logs the
  password or the access token.

## Revocation

The `ca-core` API revokes certificates by serial number, while
`CreateCertificate` returns a request ID. `RevokeCertificate` resolves the
serial through the certificate search endpoint first, then submits the status
change with the configured `RevokeReason`. Revoking an already revoked certificate returns
`ErrCertificateRevoked`; an ID with no matching certificate returns
`ErrCertificateNotFound`.

Reconciliation loops that may retry a revocation can opt out of that distinction:

```go
err := client.RevokeCertificateWithOptions(ctx, cert.ID, safetech.RevokeOptions{
	AllowAlreadyRevoked: true, // treat "already revoked" as success
})
```

A certificate that does not exist is still reported as `ErrCertificateNotFound`.

Revocation reasons (`RevokeReason`, RFC 5280):

| Constant | RFC 5280 reason | Meaning |
| --- | --- | --- |
| `RevokeReasonUnspecified` | 0 | No specific reason; use when none applies. |
| `RevokeReasonKeyCompromise` | 1 | The certificate's private key was compromised. |
| `RevokeReasonCACompromise` | 2 | The issuing CA was compromised. |
| `RevokeReasonAffiliationChanged` | 3 | The subject's affiliation with the organization changed. |
| `RevokeReasonSuperseded` | 4 | The certificate was replaced by a newer one. |
| `RevokeReasonCessationOfOperation` | 5 | The subject stopped operating. |
| `RevokeReasonPrivilegeWithdrawn` | 9 | A privilege granted by the certificate was withdrawn. |
| `RevokeReasonAACompromise` | 10 | An attribute authority was compromised. |

RFC 5280 reasons 6 (`certificateHold`) and 8 (`removeFromCRL`) are not exposed
by this client.

## Templates

`ListTemplates` returns the certificate templates configured in the CA, so
template names do not have to be hard-coded:

```go
templates, err := client.ListTemplates(ctx)
if err != nil {
	return err
}

for _, tmpl := range templates {
	if tmpl.ProtocolType != safetech.TemplateProtocolSTCA || tmpl.Deleted {
		continue
	}

	fmt.Println(tmpl.Name, tmpl.MaxValidityPeriod, tmpl.MinKeySize, tmpl.KeyUsages)
}
```

Each `CertificateTemplate` carries `ID`, `Name`, `Description`, `OID`,
`ProtocolType`, `MaxValidityPeriod` (days), `MinKeySize` (bits), `KeyUsages`
(bitmask) and `Context`. `Context.STCAEnrollment` exposes what constrains an
ST_CA request: `EnrollmentScenario`, `CryptoTypes`, `KeySizes`,
`SignatureAlgorithms`, `RequiredSubjectAlternativeNames`, `IncludeSID` and
`SupportedToken`.

Two rules the CA enforces, which the list lets you check before issuing:

- The template must be of protocol `ST_CA`; templates of other protocols are
  rejected for API issuance.
- `EnrollmentScenario` must be `STANDARD`. Templates configured as `API_ONLY` or
  `TOKEN_BASED` are rejected with an `*APIError` whose message is
  `for protocol type 'ST_CA' enrollmentScenario must be 'STANDARD'`.

Deleted templates are returned by the API and therefore by `ListTemplates`;
filter on `Deleted` when you only want usable ones.

## Retries

Transient failures are retried for idempotent requests only: token requests,
endpoint discovery and GET operations such as `ListTemplates`. `CreateCertificate`
(POST) and `RevokeCertificate` (PATCH) are never retried, because the CA gives no
way to make them idempotent and a retry could issue a second certificate.

Retried: network errors, `429`, and `5xx`. A `Retry-After` header, in seconds or
as an HTTP date, replaces the computed delay; it is capped at `MaxBackoff`.

```go
client, err := safetech.New(safetech.Config{
	BaseURL:  "https://ca.example.com:7443",
	Username: os.Getenv("STCA_USERNAME"),
	Password: os.Getenv("STCA_PASSWORD"),
	Retry: safetech.RetryPolicy{
		MaxAttempts: 5,                     // total attempts, default 3
		Backoff:     500 * time.Millisecond, // doubles per attempt, default 200ms
		MaxBackoff:  10 * time.Second,       // default 5s
	},
})
```

Set `Retry: safetech.RetryPolicy{Disabled: true}` to attempt everything once.

## Security notes

- `TLSSkipVerify` disables TLS certificate verification. Use it only against
  throwaway test installations, never in production. For a private CA, prefer a
  custom `HTTPClient` with the correct root certificates instead.
- Keep `Username`, `Password` and `ClientSecret` in environment variables or a
  secrets manager. Never commit them or embed them in source, tests or
  documentation.
- The client does not log the password or the access token. Redact
  `Authorization` headers in any HTTP tracing you add.
- Errors can carry the gateway's HTTP status and response body; review them
  before sharing logs.
- Report security issues privately, as described in [SECURITY.md](SECURITY.md).

## Testing

Unit tests need no network and no credentials:

```sh
go test -race ./...
# or
make test
```

The integration test is behind the `integration` build tag and talks to a real
CA. It issues a certificate and revokes it, so point it at a test installation
only. Credentials are read from the environment:

```sh
export STCA_BASE_URL="https://ca.example.com:7443"
export STCA_REALM_URL="https://keycloak.example.com/realms/ca" # optional; empty means discover
export STCA_USERNAME="..."
export STCA_PASSWORD="..."
export STCA_TEMPLATE="MY_TEMPLATE" # optional; auto-selected from ListTemplates

go test -tags=integration ./...
# or
make test-integration
```

If `STCA_BASE_URL`, `STCA_USERNAME` or `STCA_PASSWORD` is empty, the test skips
instead of failing. `TestIntegrationListTemplates` reads the template list, and
`TestIntegrationIssueAndRevoke` issues and revokes one certificate; when
`STCA_TEMPLATE` is empty it picks the first `ST_CA` template whose enrollment
scenario is `STANDARD`.

CI runs unit tests, linters and security scanners; the pipeline layout is
described in [docs/CI.md](docs/CI.md).

## Documentation

| Resource | Location |
| --- | --- |
| SafeTech CA API — Swagger and request examples | <https://docs.safetechlab.ru/share/e0dabuov2p/p/swagger-i-primery-zaprosov-v-api-safe-tech-ca-zPrNWFhF5l> |
| Installation, configuration and administration guides | Same documentation portal (`Установка и настройка`, `Руководства`) |
| CA CLI usage | Same portal, `CA CLI` |
| HashiCorp Vault integration | Same portal, `Интеграция SafeTech CA с HashiCorp Vault` |

The vendor documentation is written in Russian. The linked API article covers
authentication, certificate requests, certificate templates, attributes and
organizational units. The `certs/*` endpoints this client uses for issuance and
revocation are not part of that article; the client's request shapes were
derived from the API itself and are covered by the test suite.

### Full API reference (Swagger)

`ca-core` bundles a Swagger UI that is disabled by default. Enable it in
`/opt/st-ca/ca-core/application.yml`:

```yaml
springdoc:
  swagger-ui:
    enabled: true
  api-docs:
    enabled: true
```

Restart `ca-core` and open
`http://<ca-core-host>:8081/api/v1/swagger-ui/index.html`. The endpoint list is
served over plain HTTP, so use a private browsing window if your browser
rewrites the URL to HTTPS. Swagger is the authoritative reference for the
complete set of requests and parameters.

### Addressing the API

Two addressing modes are supported.

- **Gateway (default).** Set `Config.BaseURL` to the gateway endpoint, for
  example `https://ca.example.com:7443`. The client appends the
  `ca-core/api/v1` prefix that the gateway routes to `ca-core`, and derives the
  Keycloak endpoint from `/api/ui-config`. The gateway routes by the
  `x-eureka-node` header; `Config.EurekaNode` defaults to `ST CA Root`, which is
  the value the bundled installation uses.
- **Direct `ca-core`.** Set `Config.APIBaseURL` to the full API base, for
  example `http://<ca-core-host>:8081/api/v1`, and set `Config.AuthURL` to the
  realm URL. No prefix is appended and discovery is not attempted, because
  `/api/ui-config` is served by the gateway only.

## Versioning

The module follows [Semantic Versioning](https://semver.org/) and is pre-1.0
(`v0.x`). While the major version is 0, minor releases may contain breaking
changes; pin a specific version and read the [CHANGELOG](CHANGELOG.md) before
upgrading.

`Version` defaults to `dev` and can be set when building your binary:

```sh
go build -ldflags "-X github.com/edanko/safetech.Version=v1.2.3" ./cmd/yourapp
```

## License

MIT, see [LICENSE](LICENSE). Contributions are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md).
