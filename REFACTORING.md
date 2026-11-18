# Refactoring assessment

Written while preparing the repository for its first public release. It records
what was already cleaned up, then the refactors that are still worth doing,
ordered by value.

## What was cleaned up already

| Area | Change |
| --- | --- |
| Credentials | `prompt.md` held a live account password and internal hostnames; the file was deleted. The repository had zero commits, so nothing leaked into history — but the password must still be rotated. |
| Internal infrastructure | Real internal hostnames, internal template names and the internal CSR fixture are gone from code, comments and tests; placeholders (`ca.example.com`, `MY_TEMPLATE`) are used instead. |
| Package identity | The package comment said `Package stca` while the package is `safetech`; error prefixes said `stca:` and now say `safetech:`. |
| Dead dependency | `go.sum` carried a `github.com/google/uuid` hash with no matching `go.mod` requirement. The module now has no third-party dependencies at all; `go.sum` is not needed. |
| `ParsePEM` bug | It passed the PEM text to `x509.ParseCertificate`, which expects DER, so it could never succeed. It now decodes the PEM block first. |
| CSR validation | `normalizeCSR` appended a newline to any input, so the `csr == ""` check was unreachable. Requests are now PEM-decoded, parsed and signature-checked locally; malformed input fails before a network round trip. |
| Serial lookup | Only the first search page was inspected, so a request with more than 100 certificates could report "not found". The lookup now pages up to 10 pages, preferring `ACTIVE` over `REVOKED`. |
| Header escaping | `x-eureka-node` was `url.QueryEscape`d; header values need no escaping (`ST CA Root` became `ST+CA+Root`). |
| Error surface | `httpError` was unexported and offered no way to inspect a status, so callers could only string-match. It is now `HTTPError` plus `APIError`, both usable with `errors.As`/`errors.AsType`. Sentinel errors (`ErrInvalidCSR`, `ErrCertificateNotFound`, `ErrCertificateRevoked`) make recovery paths testable with `errors.Is`. |
| Dead code | `envelope.isOk` and `envelope.errString` were unused duplicates of each other; the unused Keycloak response fields and the `cloneForm` helper (replaced by `url.Values.Clone`) are gone. |
| Config validation | `New` now returns an error: `BaseURL` must be an absolute `http(s)` URL, and `TLSSkipVerify` refuses a custom transport it cannot reconfigure instead of silently ignoring it. |
| Observability | Requests carry a `User-Agent` (`safetech/<Version>`, settable via `-ldflags`) and error bodies are truncated so a large response cannot blow up error strings. |
| Tests | There was one integration test and no unit tests. The suite now covers the envelope, CSR validation, time parsing, issuance, revocation, pagination, token caching/refresh/fallback, discovery failures, TLS opt-in, concurrency and credential leakage; coverage is ~91% of statements. The live-CA test is behind the `integration` build tag and generates its CSR at run time. |

## Still worth refactoring

### P0 — correctness and API shape

1. **Give `Adapter` a `context.Context`.** The interface is fixed by the host
   application, so it currently calls `context.Background()` internally.
   `CreateCertificateContext` / `RevokeCertificateContext` exist as the migration
   path. The next major version should take `ctx` on the interface methods and
   drop the `Context` variants. Cost: one signature change in the host app.

2. **Narrow the token mutex.** `accessToken` holds the client-wide mutex across
   the Keycloak round trip, so every request blocks while one refresh is in
   flight. A refresh-in-progress channel (or `singleflight`) that only serialises
   refreshes would keep cache hits lock-free. No new dependency is needed for the
   channel version.

3. **Confirm the timestamp semantics.** The CA returns `2026-10-22T18:28:59.00000`
   with no time zone; the client interprets it as UTC. If the CA actually emits
   local time, `NotBefore`/`NotAfter` are shifted by the server's UTC offset.
   Verify against the vendor, then either document it or add an explicit
   `Config.TimeZone`.

4. **Confirm the serial-number encoding.** Revocation builds
   `/certs/{serial}/change_status` from the `serialNumber` field, URL-escaped as
   returned. If the API expects a decimal or colon-separated form there, this
   breaks for serials with a different representation. Add a fixture-based test
   as soon as a real serial is observed.

### P1 — robustness

5. **Retries.** Transient `5xx`/`429` responses surface immediately. Retry with
   backoff and `Retry-After` support for token requests and discovery (both
   idempotent). Do **not** retry `POST /certs/issue` blindly: it is not
   idempotent and may issue duplicate certificates.

6. **Idempotent revocation.** `RevokeCertificate` reports
   `ErrCertificateRevoked` for an already-revoked certificate. Reconciliation
   loops usually want that to be a success; add an option
   (`RevokeOptions{AlreadyRevoked: ...}`) instead of forcing callers to special-case
   the sentinel.

7. **Fuzz the parsers.** `decodeEnvelope` and `normalizeCSR` parse untrusted
   input. Two `Fuzz*` functions would be cheap and catch panics or runaway
   allocations.

8. **`stacktrace` in the envelope.** The CA includes a server stack trace on
   errors; it is deliberately ignored. Keep it that way (server internals are not
   ours to surface) and state it in the `APIError` docs.

9. **Certificate payload fallbacks.** Issuance requires `certificateInfo.pem`.
   Some deployments return the certificate only in
   `certificateRequest.certificate`. Support both, with the PEM/DER question
   settled by a fixture test.

### P2 — structure and tooling

10. **Keep the package flat.** One vendored API, ~900 lines: a `internal/` split
    or a DTO subpackage would add indirection without a second consumer. Revisit
    if a second SafeTech API surface is added.

11. **Reconsider the Go floor.** Using the standard-library `uuid` from Go 1.27
    removes the last dependency but requires Go 1.27+ from every consumer.
    `github.com/google/uuid` would lower the floor to Go 1.21 at the cost of one
    dependency. Decide before tagging `v1.0.0`; `v0.x` is the right time to
    change it.

12. **Example tests.** `ExampleClient_CreateCertificate` in
    `example_test.go` renders in godoc and is compiled, so the README example
    cannot rot.

13. **Coverage signal.** Cover the three error branches that still matter
    (`discoverAuth` decode failure, `requestToken` malformed JSON, `New` with a
    malformed `BaseURL`) before adding a threshold gate.
