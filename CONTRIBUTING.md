# Contributing

Thanks for improving `safetech`. This document covers the development
environment, the quality gates, and the conventions used here.

## Prerequisites

- Go 1.27 or newer (`go version`).
- `make`.
- [golangci-lint](https://golangci-lint.run/welcome/install/) for `make lint`,
  which is part of `make check`.
- Optional:
  - [gofumpt](https://github.com/mvdan/gofumpt) for `make fmt` (plain `gofmt` is
    used when gofumpt is not installed);
  - [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) and
    [gosec](https://github.com/securego/gosec) for `make security`.

Install the Go-installable tools:

```sh
go install mvdan.cc/gofumpt@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

Install golangci-lint by following its
[installation instructions](https://golangci-lint.run/welcome/install/); the
release binary or a package manager is recommended.

## Setup

```sh
git clone https://github.com/edanko/safetech-go.git
cd safetech-go
go mod download
```

## Common tasks

`make help` lists every target. The most used ones:

| Command | Effect |
| --- | --- |
| `make` / `make help` | List targets. |
| `make tidy` | `go mod tidy`. |
| `make fmt` | Format Go files with gofumpt, falling back to gofmt. |
| `make vet` | `go vet ./...`. |
| `make lint` | `golangci-lint run ./...`. |
| `make test` | `go test -race ./...`. |
| `make cover` | Unit tests with a coverage profile and printed total. |
| `make test-integration` | Live-CA integration test (needs `STCA_*` variables). |
| `make security` | `govulncheck` and `gosec`. |
| `make check` | tidy, fmt, vet, lint and test. |
| `make all` | check, cover and security. |

Run the full gate before opening a pull request:

```sh
make check
```

The equivalent raw commands:

```sh
go mod tidy
gofumpt -l -w .   # or: gofmt -l -w .
go vet ./...
golangci-lint run ./...
go test -race ./...
```

## Tests

Unit tests run without network access and without credentials:

```sh
go test -race ./...
```

The integration test lives behind the `integration` build tag. It issues a real
certificate and revokes it, so use a test installation only. Configuration comes
from the environment:

```sh
export STCA_BASE_URL="https://ca.example.com:7443"
export STCA_REALM_URL="https://keycloak.example.com/realms/ca" # optional
export STCA_USERNAME="..."
export STCA_PASSWORD="..."

go test -tags=integration ./...
# or
make test-integration
```

`STCA_REALM_URL` is optional; when it is empty, the client discovers the
Keycloak realm through the gateway's `/api/ui-config` endpoint.

## Commit and pull request style

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`,
  `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `security:`. For example:
  - `feat: add certificate search pagination`
  - `fix: return ErrCertificateNotFound when the search has no match`
  - `docs: document RevokeReason`
- Renovate opens dependency updates with the same convention
  (`chore(deps): ...`); do not rewrite automated commit messages.
- Keep pull requests focused and describe the user-visible effect.
- Add or update tests. A behavior change without a test is not complete.
- Update `CHANGELOG.md` under `Unreleased` for user-visible changes.
- Keep `README.md`, package doc comments, and the actual API in sync.

## No secrets, no internal infrastructure

Never commit any of the following:

- usernames, passwords, client secrets, access tokens or refresh tokens;
- private keys, `.pem`/`.key`/`.crt`/`.csr` files, or real CSR fixtures;
- internal hostnames, IP addresses, customer names or internal template names.

Use environment variables (`STCA_*`) for anything that authenticates, and the
placeholders from `README.md` in examples: `https://ca.example.com:7443`,
`https://keycloak.example.com/realms/ca`, `MY_TEMPLATE`, `example-user`.

If a secret reaches a commit, treat it as compromised: rotate it immediately and
report the incident as described in [SECURITY.md](SECURITY.md).

## Reporting security issues

Do not open a public issue for a vulnerability. Use the private process in
[SECURITY.md](SECURITY.md).

## CI

GitHub Actions runs the same checks: unit tests with the race detector,
linting, and security scanners. The pipeline layout is documented in
[docs/CI.md](docs/CI.md).
