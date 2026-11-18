# CI / CD

All automation lives in `.github/workflows/`. Everything runs on GitHub-hosted
`ubuntu-latest` runners with the Go toolchain required by `go.mod`.

## Pipelines

| Workflow | Triggers | What it proves |
| --- | --- | --- |
| `test.yml` (CI) | push / PR to `main`, manual | `go.mod`+`go.sum` are tidy, code vets and builds, tests pass under the race detector in shuffled order; coverage artifact per Go version |
| `lint.yml` (Lint) | push / PR to `main`, manual | `golangci-lint` v2.15.0, using the repo `.golangci.yml`, reports no findings |
| `security.yml` (Security) | push / PR to `main`, manual | no known vulnerability is reachable (govulncheck); gosec and CodeQL `security-extended` results appear in the Security tab |
| `release.yml` (Release) | tag `v*` | GoReleaser publishes a GitHub Release with a grouped changelog (no binaries) |

Go version matrix: `1.27` (the module floor) and `stable`, with `fail-fast: false`
so one toolchain failure cannot hide the other.

Coverage is uploaded as the artifact `coverage-1.27` / `coverage-stable`; there is
no Codecov upload, so no `CODECOV_TOKEN` secret is needed.

## Required status checks

Branch protection on `main` should require exactly these check names:

- `Test (Go 1.27)`
- `Test (Go stable)`
- `Lint`

The security jobs are informational: `gosec` runs with `-no-fail` and CodeQL only
reports into the Security tab, so neither can gate a merge. Their SARIF uploads
need `security-events: write`, which a fork PR's token never has, so the CodeQL
job and the gosec upload are skipped for pull requests from forks.

## Releasing

1. Merge everything intended for the release into `main`; CI must be green.
2. Tag the commit and push the tag:

   ```bash
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

3. `release.yml` runs `goreleaser release --clean`. The changelog is grouped by
   Conventional Commit prefix (`feat:`, `fix:`, `perf:`, `docs:`), and noise
   (`docs:`, `test:`, `ci:`, `chore:`, `style:`, merges) is filtered out.
4. `release.draft: false` publishes immediately; `release.prerelease: auto`
   marks tags such as `v0.2.0-rc.1` as pre-releases.
5. Nothing is compiled: consumers use `go get github.com/edanko/safetech@vX.Y.Z`.
   The tag must be SemVer (`vMAJOR.MINOR.PATCH`), otherwise Go modules reject it.

## Repo settings checklist

After pushing to GitHub (`github.com/edanko/safetech`):

- [ ] Protect `main`: require a pull request, at least 1 approval, the three
      status checks above, and up-to-date branches; disallow admin bypass.
- [ ] Actions → Workflow permissions: "Read repository contents". Only
      `release.yml` escalates (`contents: write`) and only on tag pushes.
- [ ] Enable Dependabot alerts, plus secret scanning and push protection.
- [ ] Install the **Renovate** GitHub App (`renovate.json` drives it: weekly
      window in `Europe/Moscow`, grouped Go + Actions PRs, digest-pinned actions,
      patch/digest automerge only after all checks pass).
- [ ] Do not add `CODECOV_TOKEN` or any other secret; none is referenced.

## Dependencies

The library has no third-party modules: UUIDs come from the standard-library
`uuid` package added in Go 1.27, so nothing pins `github.com/google/uuid` any
more (the stale `go.sum` entry is removed). Renovate therefore manages only
`gomod` (a no-op today) and `github-actions`.
