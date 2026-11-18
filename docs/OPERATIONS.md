# Operations

What is automated, what you must do by hand, and how to take the repository
live. The pipeline itself is described in [CI.md](CI.md); this page is the
runbook around it.

## Automated vs manual

| Concern | Owner |
| --- | --- |
| Build, vet, tests, race detector, coverage floor | `.github/workflows/test.yml` |
| Linting | `.github/workflows/lint.yml` |
| govulncheck, gosec, CodeQL | `.github/workflows/security.yml` |
| Release on tag | `.github/workflows/release.yml` + `.goreleaser.yml` |
| Dependency updates | `renovate.json` (needs the Renovate app installed) |
| **Repository settings** | **manual, once** |
| **Secrets for live tests** | **manual, optional** |
| **Cutting a release** | **manual: push a tag** |
| **Credential rotation** | **manual, on your schedule** |

## Go live, once

1. **Create the repository** and push:

   ```bash
   git remote add origin git@github.com:edanko/safetech-go.git
   git push -u origin main
   ```

   The first push is also the first time CI ever runs. Watch
   `test.yml` and `lint.yml` before tagging anything: those are the only
   untested-by-construction parts of the setup.

2. **Protect `main`** (Settings → Branches → Add branch protection rule):

   - require a pull request and at least one approval
   - require the status checks listed under
     [Required status checks](CI.md#required-status-checks)
   - require branches to be up to date before merging
   - do not allow administrators to bypass

3. **Settings → Actions → General**: set *Workflow permissions* to
   **Read repository contents**. Only `release.yml` escalates, and only on tag
   pushes.

4. **Settings → Code security**: enable **Dependabot alerts**, **secret
   scanning** and **secret scanning push protection**. No secret has ever been
   committed (the repository started empty), but push protection is what keeps
   the `STCA_PASSWORD` class of accident from happening later.

5. **Install the Renovate GitHub App** for the repository. `renovate.json`
   groups Go and GitHub Actions updates, pins actions to commit digests, and
   automerges patch/digest updates once the required checks pass.

6. **Optional — live-CA secrets.** To run the integration test in CI, add
   repository secrets `STCA_BASE_URL`, `STCA_USERNAME`, `STCA_PASSWORD` (and
   optionally `STCA_REALM_URL`, `STCA_TEMPLATE`). Prefer a dedicated service
   account with a role that may only issue against the templates you intend to
   use. `make test-integration` runs the same test locally.

## First release

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

`release.yml` then runs GoReleaser, which publishes a GitHub Release with a
grouped changelog and no binaries: the library is consumed with
`go get github.com/edanko/safetech-go@v0.1.0`.

Afterwards verify, in this order:

1. the Release page exists and the changelog is grouped correctly
2. `https://pkg.go.dev/github.com/edanko/safetech-go` renders the API docs
3. the README badges resolve (CI, Go Reference, Go version, license, Go Report
   Card) — they are dead links until step 1 completes

## Production consumer checklist

Before a service depends on this module in production:

- **Use a confidential client.** Set `Config.ClientID` and `Config.ClientSecret`
  for the `ca-gateway` client rather than the public `ca-ui` one the web UI uses.
  The vendor documentation authenticates this way, and it is what `CA CLI`
  prompts for.
- **Never set `TLSSkipVerify`.** It exists for throwaway test installations. For
  the private CA, pass an `HTTPClient` whose transport trusts the right roots.
- **Give every call a context** with a deadline. The client's default HTTP
  timeout is 60s, which is fine for a request but should not bound your whole
  operation.
- **Pin a template.** Choose an `ST_CA` template whose enrollment scenario is
  `STANDARD` (see [Templates](../README.md#templates)); `ListTemplates` reports
  the constraints so this can be asserted at startup.
- **Handle the typed errors.** `errors.Is(err, safetech.ErrCertificateRevoked)`,
  `ErrCertificateNotFound`, `ErrInvalidCSR`, and `errors.As` for `*HTTPError` /
  `*APIError`. Do not match on error strings.
- **Persist what you need.** Issuance returns the PEM and chain, but if the
  process dies before writing them the certificate is only recoverable through
  `GetCertificate(ctx, serial)` — so store `SerialNumber` (or the request `ID`
  for revocation) in the same transaction that records success.
- **Keep the credential out of the source tree.** `Config.Username` /
  `Config.Password` belong in an environment variable or a secret manager. The
  client never logs them, but your own configuration loading might.

## Ongoing maintenance

| Cadence | Task |
| --- | --- |
| Weekly | Review Renovate PRs; the Go floor bump in particular is worth a look, since raising it drops older toolchains for every consumer |
| When the Security tab turns red | Triage gosec/CodeQL findings. `gosec` runs with `-no-fail` on purpose, so nothing blocks a merge; the SARIF results are the signal |
| When a test fails on the coverage floor | The floor is 90% and the package sits around 96%; a drop means new code arrived without tests |
| On your credential policy | Rotate the CA service-account password and the Keycloak client secret |

## Known gaps

Two recommendations are not wired yet, on purpose, because both need repository
state that does not exist before the first push:

- **Renovate can raise the Go floor.** The `gomod` manager updates the `go`
  directive, so `go 1.27.0` will drift upwards and silently drop older
  toolchains. Add a `packageRules` entry matching the `golang-version`
  dependency type and set `automerge: false` if the floor must stay put.
- **No scheduled live-CA test.** Every workflow is push/PR or manual, so vendor
  API drift is only caught when someone runs `make test-integration`. A weekly
  `schedule:` trigger gated on the `STCA_*` secrets would close that gap.
