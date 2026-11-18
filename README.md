# safetech

Go client for the SafeTech CA certificate authority (`ca-core` REST API):
issue X.509 user certificates from a CSR and revoke them.

[![CI](https://img.shields.io/github/actions/workflow/status/edanko/safetech/test.yml?branch=main)](https://github.com/edanko/safetech/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/edanko/safetech.svg)](https://pkg.go.dev/github.com/edanko/safetech)
[![Go Version](https://img.shields.io/github/go-mod/go-version/edanko/safetech)](https://go.dev/)
[![License: MIT](https://img.shields.io/github/license/edanko/safetech)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/edanko/safetech)](https://goreportcard.com/report/github.com/edanko/safetech)

## Features

- Issues certificates from PEM-encoded PKCS#10 CSRs against a named CA template.
- Validates the CSR locally (PEM decode, parse, self-signature check) before any
  request is sent; invalid requests return `ErrInvalidCSR`.
- Revokes certificates by the ID returned at issuance, with RFC 5280 revocation reasons.
- Authenticates against Keycloak with cached, automatically refreshed access tokens.
- Provides context-aware variants of every operation.
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
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/edanko/safetech"
)

func main() {
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

	cert, err := client.CreateCertificate(csrPEM, "MY_TEMPLATE")
	if err != nil {
		log.Fatalf("issue certificate: %v", err)
	}
	fmt.Printf("serial: %s\n", cert.SerialNumber)
	fmt.Printf("status: %s\n", cert.Status)
	fmt.Printf("valid:  %s .. %s\n",
		cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))

	if err := client.RevokeCertificate(cert.ID); err != nil {
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
| `ClientID` | `ca-ui` (or the discovered client ID) | OIDC client used for authentication. |
| `ClientSecret` | empty | Client secret for confidential clients. Leave empty for the public `ca-ui` client. |
| `Username` | required | Account for the password grant. |
| `Password` | required | Password for the password grant. |
| `EurekaNode` | `ST CA Root` | CA node identity, sent as the `x-eureka-node` header. |
| `RevokeReason` | `RevokeReasonUnspecified` | Revocation reason used by `RevokeCertificate`. |
| `TLSSkipVerify` | `false` | Disables server certificate verification. Test environments only; see [Security notes](#security-notes). |
| `HTTPClient` | `nil` (internal default) | Optional custom `*http.Client`. When `TLSSkipVerify` is set, the custom transport must be an `*http.Transport`. |
| `UserAgent` | `safetech/<Version>` | `User-Agent` header sent to the API. |

## Authentication

The gateway protects the `ca-core` API with Keycloak. The client uses the
Resource Owner Password Credentials grant against the `ca-ui` public OIDC
client, the same client the SafeTech CA web UI uses.

- **Discovery.** Unless `AuthURL` is set, the client calls
  `{BaseURL}/api/ui-config`, which advertises the Keycloak URL, realm and client
  ID. Set `AuthURL` to skip that call, for example when the gateway does not
  expose `ui-config` or when you address `ca-core` directly.
- **Token lifecycle.** The access token is obtained lazily, cached, and
  refreshed with the refresh-token grant before it expires. If the refresh
  fails, the client falls back to the password grant.
- **Confidential clients.** Set `ClientSecret` when the OIDC client is not
  public. The default `ca-ui` client is public, so `ClientSecret` normally
  stays empty.
- Credentials are taken from the configuration only. The client never logs the
  password or the access token.

## Adapter interface

```go
type Adapter interface {
	CreateCertificate(csrPEM []byte, templateName string) (*UserCertificate, error)
	RevokeCertificate(certificateID uuid.UUID) error
}
```

`uuid` here is the Go 1.27 standard-library package. `*Client` implements
`Adapter`; the interface exists so that call sites which need only these two
operations do not depend on the HTTP client and can be tested with a fake.

Pass the client (or any other implementation) into your own constructor:

```go
type Enroller struct {
	ca safetech.Adapter
}

func NewEnroller(ca safetech.Adapter) *Enroller { return &Enroller{ca: ca} }
```

```go
client, err := safetech.New(cfg)
if err != nil {
	return err
}
enroller := NewEnroller(client)
```

The `Adapter` methods have no `context.Context` parameter and use
`context.Background()` internally. When you need cancellation or deadlines,
keep a `*Client` and call `CreateCertificateContext` or
`RevokeCertificateContext` instead.

## Revocation

The `ca-core` API revokes certificates by serial number, while
`CreateCertificate` returns a request ID. `RevokeCertificate` and
`RevokeCertificateContext` resolve the serial through the certificate search
endpoint first, then submit the status change with the configured
`RevokeReason`. Revoking an already revoked certificate returns
`ErrCertificateRevoked`; an ID with no matching certificate returns
`ErrCertificateNotFound`.

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
export STCA_TEMPLATE="MY_TEMPLATE" # optional; defaults to MY_TEMPLATE

go test -tags=integration ./...
# or
make test-integration
```

If `STCA_BASE_URL`, `STCA_USERNAME` or `STCA_PASSWORD` is empty, the test skips
instead of failing.

CI runs unit tests, linters and security scanners; the pipeline layout is
described in [docs/CI.md](docs/CI.md).

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
