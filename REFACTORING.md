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

## Refactors landed

Done while live API access was available, each verified against a SafeTech CA v3
test installation:

| Refactor | Result |
| --- | --- |
| Token cache no longer holds the client mutex across the Keycloak round trip | One goroutine fetches, the rest wait on a completion channel; 12 concurrent callers produced a single token request. |
| Direct `ca-core` addressing | `Config.APIBaseURL` takes the full API base (`…/api/v1`); verified against `ca-core` with the gateway bypassed. |
| Bounded retries | `Config.Retry` retries network errors, `429` and `5xx` for token, discovery and GET requests only, honouring `Retry-After`; a transient gateway `503` was retried and surfaced after the attempts. |
| Idempotent revocation | `RevokeCertificateWithOptions` with `AllowAlreadyRevoked` returns success for an already revoked certificate. |
| Parser fuzzing | `FuzzNormalizeCSR`, `FuzzDecodeEnvelope`, `FuzzParseSTCATime`, `FuzzParseRetryAfter`, `FuzzTemplatePayloadDecoding`. |
| Example tests | `Example` functions compile in `go test`, so the README snippets cannot rot. |

## Still worth refactoring

### Robustness

1. **Certificate payload fallbacks.** Issuance requires `certificateInfo.pem`.
   Some deployments may return the certificate only in
   `certificateRequest.certificate`. Support both, with the PEM/DER question
   settled by a fixture test rather than by guessing.

### Structure and tooling

2. **Keep the package flat.** One vendored API, ~1.2k lines: an `internal/` split
   or a DTO subpackage would add indirection without a second consumer. Revisit
   if a second SafeTech API surface is added.

3. **Reconsider the Go floor.** Using the standard-library `uuid` from Go 1.27
   removes the last dependency but requires Go 1.27+ from every consumer.
   `github.com/google/uuid` would lower the floor to Go 1.21 at the cost of one
   dependency. Decide before tagging `v1.0.0`; `v0.x` is the right time to
   change it.

4. **Coverage signal.** A few error branches are still unexercised
   (`discoverAuth` decode failure, `requestToken` malformed JSON). Cover them, or
   add a threshold gate to CI, but not both as a substitute for the other.

## API behaviour verified against a live instance

Checked against a SafeTech CA v3 test installation (through the gateway), which
the test suite now mirrors:

| Observation | Evidence |
| --- | --- |
| The response envelope and `payload` extraction match `decodeEnvelope`. | `GET /templates` and `POST /certs/issue` returned `errorCode`/`errorMessage`/`stacktrace`/`payload`. |
| `x-eureka-node: ST CA Root` is what the gateway needs to route a request. | Without it the gateway answers `503`; with it, `200`. The client default is correct. |
| `GET /templates` returns `payload` as a plain array, not a page. | 52 templates in one response; no paging metadata. |
| Timestamps are UTC without a zone suffix. | A certificate issued at 18:58 UTC parsed to `NotBefore` 18:58 UTC; Spring error bodies report `+00:00`. Reading them as UTC is correct. |
| The serial number is lowercase hex without a prefix. | `serialNumber` `03dc`; `PATCH /certs/03dc/change_status` revoked it successfully. |
| `ST_CA` issuance requires a template whose `enrollmentScenario` is `STANDARD`. | `API_ONLY`/`TOKEN_BASED` templates are rejected with `errorCode` 101 and "for protocol type 'ST_CA' enrollmentScenario must be 'STANDARD'". |
| An already revoked certificate is reported, not silently accepted. | Second `RevokeCertificate` returns `ErrCertificateRevoked`. |
