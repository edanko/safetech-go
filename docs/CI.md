# CI / CD

All automation lives in `.github/workflows/`. Everything runs on GitHub-hosted
`ubuntu-latest` runners with the Go toolchain required by `go.mod`.

This page describes the pipeline. The manual work around it — repository
settings, secrets, the first release and production guidance — is in
[OPERATIONS.md](OPERATIONS.md).

## Pipelines

| Workflow | Triggers | What it proves |
| --- | --- | --- |
| `test.yml` (CI) | push / PR to `main`, manual | `go.mod`+`go.sum` are tidy, code vets and builds, tests pass under the race detector in shuffled order; library-package coverage must stay at or above 90%; coverage artifact per Go version |
| `lint.yml` (Lint) | push / PR to `main`, manual | `golangci-lint` v2.15.0, using the repo `.golangci.yml`, reports no findings |
| `security.yml` (Security) | push / PR to `main`, manual | no known vulnerability is reachable (govulncheck); gosec and CodeQL `security-extended` results appear in the Security tab |
| `release.yml` (Release) | tag `v*` | GoReleaser publishes a GitHub Release with a grouped changelog (no binaries) |

Go version matrix: `1.27` (the module floor) and `stable`, with `fail-fast: false`
so one toolchain failure cannot hide the other.

Coverage is uploaded as the artifact `coverage-1.27` / `coverage-stable`; there is
no Codecov upload, so no `CODECOV_TOKEN` secret is needed. The `1.27` leg also
re-runs the library package alone and fails if statement coverage drops below the
90% floor (`COVERAGE_FLOOR` in `test.yml`).

## Required status checks

Branch protection on `main` should require exactly these check names:

- `Test (Go 1.27)`
- `Test (Go stable)`
- `Lint`

The security jobs are informational: `gosec` runs with `-no-fail` and CodeQL only
reports into the Security tab, so neither can gate a merge. That depends on there
being a Security tab: code scanning is free on public repositories but needs
GitHub Advanced Security on private ones, so on a private repository CodeQL is
skipped and a `gosec` finding fails the job instead of uploading, which keeps it
visible. Set the repository variable `ENABLE_CODE_SCANNING` to `true` on a
private repository that does have the feature. Their SARIF uploads
need `security-events: write`, which a fork PR's token never has, so the CodeQL
job and the gosec upload are skipped for pull requests from forks.

## Releasing

Pushing a `v*` tag runs `release.yml`, which invokes
`goreleaser release --clean`:

- the changelog is grouped by Conventional Commit prefix (`feat:`, `fix:`,
  `perf:`, `docs:`) and noise (`docs:`, `test:`, `ci:`, `chore:`, `style:`,
  merges) is filtered out
- `release.draft: false` publishes immediately, and `release.prerelease: auto`
  marks tags such as `v0.2.0-rc.1` as pre-releases
- nothing is compiled; the release is a GitHub Release, and consumers use
  `go get github.com/edanko/safetech-go@vX.Y.Z`
- the tag must be SemVer (`vMAJOR.MINOR.PATCH`), otherwise Go modules reject it

The release procedure itself — merge, tag, push, verify — is in
[OPERATIONS.md](OPERATIONS.md#first-release).

## Dependencies

The library has no third-party modules: UUIDs come from the standard-library
`uuid` package added in Go 1.27, so nothing pins `github.com/google/uuid` any
more (the stale `go.sum` entry is removed). Renovate therefore manages only
`gomod` (a no-op today) and `github-actions`.
