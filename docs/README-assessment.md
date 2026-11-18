# Documentation assessment

Pre-publish audit of the repository state as of 2026-11-18. Findings describe
what the documentation had to account for; the code rewrite that accompanies
publication resolves some of them, as noted under Status.

## Findings

| # | Finding (state at audit time) | Documentation consequence |
| --- | --- | --- |
| 1 | A local notes file (`prompt.md`) contained live credentials and internal hostnames: gateway and Keycloak URLs, internal template names, and a username/password pair. | The file was deleted and must never be committed. Credentials exposed in it must be rotated. Examples use `https://ca.example.com:7443`, `https://keycloak.example.com/realms/ca` and `MY_TEMPLATE`. |
| 2 | Repository had zero commits, no remote and no tags. | Nothing in the tree was public yet; examples were written against the API contract rather than published history. |
| 3 | Package doc comment said `Package stca`, while the package is `safetech` and the module is `github.com/edanko/safetech`. | README and CONTRIBUTING refer to `safetech` only. The package comment had to be corrected in code. |
| 4 | `go.sum` carried a `github.com/google/uuid` checksum while `go.mod` had no matching `require`. | The module has zero dependencies and imports the Go 1.27 standard-library `uuid` package. `go.sum` must be emptied, not hand-edited. |
| 5 | No `README.md`, `LICENSE`, `CHANGELOG.md`, `CONTRIBUTING.md` or `SECURITY.md` existed. | All were created, with `README.md` as the reference document. |
| 6 | The integration test's doc comment pointed at a non-existent `./stca` package path, the test had no `//go:build integration` constraint, and it embedded a real CSR whose subject carried an internal identity with an internal CA template name. | README and CONTRIBUTING document `go test -tags=integration ./...` from the repository root, with a locally read or generated CSR and the `MY_TEMPLATE` placeholder. |
| 7 | No `.gitignore` existed, so binaries, coverage output, `.env` files and key material were not excluded from a future commit. | Added `.gitignore` covering Go artifacts, `coverage.out`, `.env*`, `*.pem`, `*.key`, `*.crt`, `*.csr` and `secrets/**`. |

## Status after the rewrite

- The package comment now names `safetech`.
- The integration test carries `//go:build integration` and generates its CSR
  through `internal/testutil`, so no internal identity or template name remains.
- No internal hostnames are left in the library or test sources; documentation
  uses placeholder URLs throughout.
- `prompt.md` is deleted from the working tree. Credential rotation is still
  outstanding and cannot be done by a documentation change.
- `go mod tidy` removed the dead `google/uuid` entry. The module has no
  dependencies left, so `go.sum` was deleted rather than committed empty.
- `docs/CI.md` now exists and is linked from `README.md` and `CONTRIBUTING.md`.

## Decisions

- The README is the single reference document; `docs/EXAMPLES.md` holds recipes
  and the changelog records user-visible changes.
- Only public product names appear (SafeTech CA, `ca-core`, Keycloak).
  Infrastructure is represented by placeholder URLs and template names.
- Local CSR validation, typed errors and the context-first method signatures
  are documented as public behavior; the library exports no interface.
- CI details belong to `docs/CI.md`; the README links to it instead of
  duplicating the workflow.

## Follow-ups

- Rotate the credentials that were present in the working tree.
- Confirm the release date of `0.1.0` when the tag is created.
