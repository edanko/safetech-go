package safetech

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// envelope is the standard response envelope of the ca-core API. A successful
// response carries a zero errorCode and an empty errorMessage, with the data
// in the "payload" field.
type envelope struct {
	ErrorCode    int    `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
}

// err reports the envelope as an [*APIError], or nil when the envelope
// describes a successful response.
func (e envelope) err() error {
	msg := strings.TrimSpace(e.ErrorMessage)
	if e.ErrorCode == 0 && msg == "" {
		return nil
	}

	return &APIError{Code: e.ErrorCode, Message: msg}
}

// APIError is returned when the CA reports a failure inside an otherwise
// successful HTTP response. Use errors.As or errors.AsType to inspect it.
//
// The CA also sends a server-side stacktrace in its error envelope. It is
// deliberately not surfaced: it describes the CA's internals, not the caller's
// request, and it is not stable enough to match on.
type APIError struct {
	// Code is the errorCode reported by the CA. It is 0 when the CA
	// reported a message without a code.
	Code int
	// Message is the errorMessage reported by the CA.
	Message string
}

func (e *APIError) Error() string {
	if e.Code == 0 {
		return "safetech: api error: " + e.Message
	}

	return fmt.Sprintf("safetech: api error %d: %s", e.Code, e.Message)
}

// HTTPError is returned when the CA gateway answers with a status code of 400
// or above. Use errors.As or errors.AsType to inspect it.
type HTTPError struct {
	// StatusCode is the HTTP status code of the response.
	StatusCode int
	// Body is the response body, trimmed and truncated to 512 bytes.
	Body string
	// RetryAfter is the delay requested by the response's Retry-After
	// header, or zero when the header is absent or unusable.
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("safetech: http %d", e.StatusCode)
	}

	return fmt.Sprintf("safetech: http %d: %s", e.StatusCode, e.Body)
}

// maxRetryAfter caps a server-provided retry delay.
const maxRetryAfter = 24 * time.Hour

// nullLiteral is the JSON representation of an absent payload.
var nullLiteral = []byte("null")

// do performs an authenticated JSON request against the CA API and decodes the
// payload of the response envelope into out. out may be nil when the payload is
// not needed.
//
// GET requests are retried according to Config.Retry; POST and PATCH requests are
// not, because issuing and revoking certificates is not idempotent.
func (c *Client) do(ctx context.Context, method, path string, reqBody, out any) error {
	attempt := func() error {
		return c.doOnce(ctx, method, path, reqBody, out)
	}

	if method == http.MethodGet {
		return c.retryable(ctx, method+" "+path, attempt)
	}

	return attempt()
}

// doOnce performs a single authenticated JSON request.
func (c *Client) doOnce(ctx context.Context, method, path string, reqBody, out any) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}

	var body io.Reader

	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("safetech: marshal request %s: %w", path, err)
		}

		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.apiBase+path, body)
	if err != nil {
		return fmt.Errorf("safetech: build request %s: %w", path, err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", c.userAgent)
	// The CA gateway routes requests to the instance named by this header.
	// It is sent verbatim: HTTP header values must not be URL-escaped.
	req.Header.Set("x-eureka-node", c.node)

	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("safetech: %s %s: %w", method, path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("safetech: %s %s: read response: %w", method, path, err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return newHTTPError(resp.StatusCode, resp.Header, raw)
	}

	if err := decodeEnvelope(raw, out); err != nil {
		return fmt.Errorf("safetech: %s %s: %w", method, path, err)
	}

	return nil
}

// decodeEnvelope validates the ca-core response envelope and unmarshals its
// payload into out. out may be nil when the payload is not needed.
func decodeEnvelope(raw []byte, out any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}

	var env struct {
		envelope
		Payload json.RawMessage `json:"payload"`
	}

	if err := json.Unmarshal(trimmed, &env); err != nil {
		return fmt.Errorf("decode response envelope: %w", err)
	}

	if err := env.err(); err != nil {
		return err
	}

	payload := bytes.TrimSpace(env.Payload)
	if out == nil || len(payload) == 0 || bytes.Equal(payload, nullLiteral) {
		return nil
	}

	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decode response payload: %w", err)
	}

	return nil
}

// newHTTPError builds an [*HTTPError] from a response, keeping the body and the
// server's Retry-After hint.
func newHTTPError(status int, header http.Header, raw []byte) *HTTPError {
	return &HTTPError{
		StatusCode: status,
		Body:       truncate(strings.TrimSpace(string(raw)), maxErrorBodyBytes),
		RetryAfter: parseRetryAfter(header.Get("Retry-After")),
	}
}

// parseRetryAfter interprets a Retry-After header value, which carries either a
// number of seconds or an HTTP date.
func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	if seconds, err := strconv.Atoi(value); err == nil {
		switch {
		case seconds <= 0:
			return 0
		// Clamp instead of overflowing: a large value would multiply past the
		// range of time.Duration and come out negative.
		case seconds > int(maxRetryAfter/time.Second):
			return maxRetryAfter
		}

		return time.Duration(seconds) * time.Second
	}

	if when, err := http.ParseTime(value); err == nil {
		if delay := time.Until(when); delay > 0 {
			return delay
		}
	}

	return 0
}

// truncate shortens s to at most limit bytes without splitting a UTF-8 rune.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}

	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}

	return s[:cut] + "…"
}

// post performs a POST request against the CA API.
func (c *Client) post(ctx context.Context, path string, reqBody, out any) error {
	return c.do(ctx, http.MethodPost, path, reqBody, out)
}

// get performs a GET request against the CA API.
func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// patch performs a PATCH request against the CA API.
func (c *Client) patch(ctx context.Context, path string, reqBody, out any) error {
	return c.do(ctx, http.MethodPatch, path, reqBody, out)
}

// DTOs of the ca-core API.

// issueRequest is the body of POST /certs/issue.
type issueRequest struct {
	// Type selects the request content format. The backend enumerates
	// CA_CHALLENGE, NETSCAPE_KEYGEN, CMS, PKCS10,
	// SIGNED_CERTIFICATE_TIMESTAMP_LIST and CMC, but every type except
	// PKCS10 is rejected with "can't be used now" by the current builds,
	// so PKCS10 is the only supported value.
	Type string `json:"type"`
	// RequestContent is the PEM-encoded PKCS#10 certificate request.
	RequestContent string `json:"request_content"`
	// SID is an optional subject identifier.
	SID any `json:"sid"`
	// TemplateName is the name of the CA certificate template.
	TemplateName string `json:"templateName"`
}

// issuePayload is the value of the "payload" field of the issue response.
type issuePayload struct {
	CertificateInfo    certPayload `json:"certificateInfo"`
	CertificateRequest reqPayload  `json:"certificateRequest"`
}

// reqPayload describes the certificate request created or accepted by the CA.
type reqPayload struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Status       string `json:"status"`
	TemplateID   string `json:"templateId"`
	Certificate  string `json:"certificate"`
	DownloadFlag bool   `json:"downloadAvailable"`
}

// certPayload is the certificate info object of the API.
type certPayload struct {
	Status        string         `json:"status"`
	SerialNumber  string         `json:"serialNumber"`
	PEM           string         `json:"pem"`
	Chain         string         `json:"chain"`
	FullChain     string         `json:"fullchain"`
	Root          string         `json:"root"`
	NotBefore     string         `json:"notBefore"`
	NotAfter      string         `json:"notAfter"`
	RequestID     string         `json:"requestId"`
	TemplateID    string         `json:"templateId"`
	SubjectDn     map[string]any `json:"subjectDn"`
	IssuerDn      map[string]any `json:"issuerDn"`
	KeyUsages     []string       `json:"keyUsages"`
	ExtendedKU    []string       `json:"extendedKeyUsages"`
	IsCA          bool           `json:"isCA"`
	SANsBase64    string         `json:"subjectAlternativeNames"`
	PKCS7         string         `json:"pkcs7"`
	DNHash        string         `json:"dnHash"`
	SignatureAlgo string         `json:"signatureAlgo"`
	PublicKey     string         `json:"publicKey"`
}

// changeStatusRequest is the body of PATCH /certs/{serial}/change_status.
type changeStatusRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// searchRequest is the body of POST /certs/search.
type searchRequest struct {
	Filters []searchFilter `json:"filters"`
	Sorts   []searchSort   `json:"sorts"`
	Page    int            `json:"page"`
	Size    int            `json:"size"`
}

// searchFilter is one filter of a certificate search.
type searchFilter struct {
	Key       string   `json:"key"`
	FieldType string   `json:"fieldType"`
	Operator  string   `json:"operator"`
	Value     string   `json:"value,omitempty"`
	Values    []string `json:"values,omitempty"`
}

// searchSort is one sort of a certificate search.
type searchSort struct {
	Key       string `json:"key"`
	Direction string `json:"direction"`
}

// searchPayload is the value of the "payload" field of the search response.
type searchPayload struct {
	Content    []certPayload `json:"content"`
	TotalItems int           `json:"totalItems"`
}

// templatePayload is one entry of the GET /templates response.
type templatePayload struct {
	ID                string                  `json:"id"`
	Name              string                  `json:"name"`
	Description       string                  `json:"description"`
	OID               string                  `json:"oid"`
	ProtocolType      string                  `json:"protocolType"`
	MaxValidityPeriod int                     `json:"maxValidityPeriod"`
	MinKeySize        int                     `json:"minKeySize"`
	KeyUsages         int                     `json:"keyUsages"`
	Deleted           bool                    `json:"deleted"`
	Context           *templateContextPayload `json:"context"`
}

// templateContextPayload is the enrollment context of a template. Either part
// may be absent depending on the template protocol, and context itself may be
// null for templates created without one.
type templateContextPayload struct {
	STCAEnrollment *stcaEnrollmentPayload `json:"stcaEnrollmentContext"`
	Common         *commonContextPayload  `json:"commonContext"`
}

// stcaEnrollmentPayload is the ST_CA-specific enrolment configuration.
type stcaEnrollmentPayload struct {
	EnrollmentScenario              string   `json:"enrollmentScenario"`
	CryptoTypes                     []string `json:"cryptoTypes"`
	KeySizes                        []int    `json:"keySizes"`
	SignatureAlgorithms             []string `json:"signatureAlgorithms"`
	RequiredSubjectAlternativeNames []string `json:"requiredSubjectAlternativeNames"`
	IncludeSID                      bool     `json:"includeSID"`
	SupportedToken                  string   `json:"supportedToken"`
	InstallRutokenConfig            bool     `json:"installRutokenConfig"`
}

// commonContextPayload is the protocol-independent enrolment configuration.
type commonContextPayload struct {
	CheckUniquePublicKeys  bool `json:"checkUniquePublicKeys"`
	ApplyKeyUsages         bool `json:"applyKeyUsages"`
	ApplyExtendedKeyUsages bool `json:"applyExtendedKeyUsages"`
}

// template converts a template payload into the domain type.
func (p templatePayload) template() CertificateTemplate {
	template := CertificateTemplate{
		ID:                p.ID,
		Name:              p.Name,
		Description:       p.Description,
		OID:               p.OID,
		ProtocolType:      TemplateProtocol(p.ProtocolType),
		MaxValidityPeriod: p.MaxValidityPeriod,
		MinKeySize:        p.MinKeySize,
		KeyUsages:         p.KeyUsages,
		Deleted:           p.Deleted,
	}

	if p.Context == nil {
		return template
	}

	if stca := p.Context.STCAEnrollment; stca != nil {
		template.Context.STCAEnrollment = &STCAEnrollmentContext{
			EnrollmentScenario:              stca.EnrollmentScenario,
			CryptoTypes:                     stca.CryptoTypes,
			KeySizes:                        stca.KeySizes,
			SignatureAlgorithms:             stca.SignatureAlgorithms,
			RequiredSubjectAlternativeNames: stca.RequiredSubjectAlternativeNames,
			IncludeSID:                      stca.IncludeSID,
			SupportedToken:                  stca.SupportedToken,
			InstallRutokenConfig:            stca.InstallRutokenConfig,
		}
	}

	if common := p.Context.Common; common != nil {
		template.Context.Common = &CommonContext{
			CheckUniquePublicKeys:  common.CheckUniquePublicKeys,
			ApplyKeyUsages:         common.ApplyKeyUsages,
			ApplyExtendedKeyUsages: common.ApplyExtendedKeyUsages,
		}
	}

	return template
}
