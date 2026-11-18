// Package safetech implements a client for the SafeTech CA REST API
// ("ca-core").
//
// The client issues X.509 certificates from PEM-encoded PKCS#10 requests and
// revokes them again. Authentication uses the Keycloak Resource Owner Password
// Credentials grant with the public "ca-ui" OIDC client, the same client the
// SafeTech management web UI uses. Access tokens are obtained lazily, cached,
// refreshed through the refresh_token grant, and re-acquired with the password
// grant when refreshing fails.
//
// A [Client] is safe for concurrent use by multiple goroutines.
package safetech

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"uuid"
)

// RevokeReason is an RFC 5280 revocation reason code used by the CA API.
type RevokeReason string

// Revocation reason codes accepted by the CA API.
const (
	RevokeReasonUnspecified          RevokeReason = "UNSPECIFIED"
	RevokeReasonKeyCompromise        RevokeReason = "KEY_COMPROMISE"
	RevokeReasonCACompromise         RevokeReason = "CA_COMPROMISE"
	RevokeReasonAffiliationChanged   RevokeReason = "AFFILIATION_CHANGED"
	RevokeReasonSuperseded           RevokeReason = "SUPERSEDED"
	RevokeReasonCessationOfOperation RevokeReason = "CESSATION_OF_OPERATION"
	RevokeReasonPrivilegeWithdrawn   RevokeReason = "PRIVILEGE_WITHDRAWN"
	RevokeReasonAACompromise         RevokeReason = "AA_COMPROMISE"
)

// Config configures a [Client]. Only BaseURL, Username and Password are
// required; every other field has a documented default.
type Config struct {
	// BaseURL is the HTTP endpoint of the CA gateway, for example
	// "https://ca.example.com:7443". The "ca-core/api/v1" prefix is
	// appended automatically.
	//
	// The Keycloak endpoint and realm are discovered from the public
	// "{BaseURL}/api/ui-config" endpoint unless AuthURL is set.
	//
	// Ignored when APIBaseURL is set.
	BaseURL string
	// APIBaseURL is the full base URL of the ca-core API itself, for example
	// "http://ca-core.example.com:8081/api/v1". Set it to address ca-core
	// directly instead of through the gateway: no path prefix is appended and
	// BaseURL is ignored. AuthURL is then required, because the gateway's
	// /api/ui-config discovery endpoint is not available.
	APIBaseURL string
	// AuthURL is an optional explicit URL of the Keycloak realm, for
	// example "https://keycloak.example.com/realms/ca". When set, discovery
	// through /api/ui-config is skipped. It is required when the API is
	// addressed directly instead of through the gateway.
	AuthURL string
	// ClientID is the OIDC client used for authentication. It defaults to
	// the client id advertised by /api/ui-config, or "ca-ui" when that or
	// AuthURL is not set.
	ClientID string
	// ClientSecret authenticates a confidential client. Leave it empty for
	// public clients such as "ca-ui".
	ClientSecret string
	// Username is the account authenticating to the CA.
	Username string
	// Password is the password of that account.
	Password string
	// EurekaNode names the CA instance behind the gateway and is sent in
	// the "x-eureka-node" header. It defaults to "ST CA Root".
	EurekaNode string
	// RevokeReason is the revocation reason used by
	// [Client.RevokeCertificate]. It defaults to RevokeReasonUnspecified.
	RevokeReason RevokeReason
	// TLSSkipVerify disables verification of the server TLS certificate.
	// Use it only in test environments. It cannot be combined with an
	// [Config.HTTPClient] whose transport is not an *http.Transport.
	TLSSkipVerify bool
	// HTTPClient optionally provides a custom HTTP client. Its transport is
	// cloned, not modified, when TLSSkipVerify is set.
	HTTPClient *http.Client
	// UserAgent overrides the "safetech/<Version>" User-Agent header.
	UserAgent string
	// Retry configures retries for idempotent requests. The zero value retries
	// transient failures twice, with exponential backoff.
	Retry RetryPolicy
}

// Error values reported by the client. They are wrapped by the returned
// errors and can be tested with errors.Is.
var (
	// ErrInvalidCSR reports a certificate signing request that is not a
	// usable PEM-encoded PKCS#10 request.
	ErrInvalidCSR = errors.New("safetech: invalid certificate signing request")
	// ErrCertificateNotFound reports that the CA has no certificate for the
	// given request id.
	ErrCertificateNotFound = errors.New("safetech: certificate not found")
	// ErrCertificateRevoked reports that the certificate is already revoked.
	ErrCertificateRevoked = errors.New("safetech: certificate is already revoked")
)

// Wire-level constants of the ca-core and Keycloak APIs.
const (
	apiPrefix    = "ca-core/api/v1"
	tokenPath    = "/protocol/openid-connect/token"
	uiConfigPath = "/api/ui-config"

	pathIssue        = "/certs/issue"
	pathSearch       = "/certs/search"
	pathChangeStatus = "/certs/%s/change_status"
	pathTemplates    = "/templates"

	defaultNode     = "ST CA Root"
	defaultClientID = "ca-ui"

	issueTypePKCS10 = "PKCS10"
	fieldTypeString = "STRING"
	operatorEqual   = "EQUAL"

	statusActive  = "ACTIVE"
	statusRevoked = "REVOKED"
)

// Tuning constants.
const (
	tokenMargin        = 15 * time.Second
	defaultHTTPTimeout = 60 * time.Second

	// maxResponseBytes caps how much of a ca-core response body is read.
	maxResponseBytes = 32 << 20
	// maxTokenResponseBytes caps how much of a Keycloak token response is
	// read.
	maxTokenResponseBytes = 2 << 20
	// maxUIConfigBytes caps how much of the discovery response is read.
	maxUIConfigBytes = 1 << 20
	// maxErrorBodyBytes is how much of a failing response body is kept in
	// errors.
	maxErrorBodyBytes = 512

	// searchPageSize is the page size used when looking up a certificate.
	searchPageSize = 100
	// maxSearchPages bounds how many search pages are requested.
	maxSearchPages = 10
)

// Client is a SafeTech CA REST client. It is safe for concurrent use.
type Client struct {
	cfg       Config
	apiBase   string
	node      string
	userAgent string
	http      *http.Client
	retry     retryPolicy

	// mu guards the cached token and the resolved auth endpoints. Token
	// requests themselves run without it, coordinated by refresh, so cache
	// hits never wait for a token round trip.
	mu      sync.Mutex
	token   *cachedToken
	auth    *authEndpoints
	refresh *tokenRefresh
}

// authEndpoints is the resolved Keycloak token endpoint and OIDC client id.
type authEndpoints struct {
	tokenURL string
	clientID string
}

// New returns a ready-to-use [Client]. It validates the configuration but
// performs no network calls; the access token is obtained on the first
// request.
func New(cfg Config) (*Client, error) {
	apiBase, err := resolveAPIBase(&cfg)
	if err != nil {
		return nil, err
	}

	httpClient, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	cfg.AuthURL = strings.TrimSuffix(strings.TrimSpace(cfg.AuthURL), "/")
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.EurekaNode = cmp.Or(strings.TrimSpace(cfg.EurekaNode), defaultNode)
	cfg.RevokeReason = cmp.Or(cfg.RevokeReason, RevokeReasonUnspecified)
	cfg.UserAgent = cmp.Or(strings.TrimSpace(cfg.UserAgent), defaultUserAgent())

	return &Client{
		cfg:       cfg,
		apiBase:   apiBase,
		node:      cfg.EurekaNode,
		userAgent: cfg.UserAgent,
		http:      httpClient,
		retry:     newRetryPolicy(cfg.Retry),
	}, nil
}

// resolveAPIBase derives the base URL of the ca-core API from the configuration,
// normalising the URL fields it reads.
func resolveAPIBase(cfg *Config) (string, error) {
	if explicit := strings.TrimSpace(cfg.APIBaseURL); explicit != "" {
		if err := validateBaseURL("Config.APIBaseURL", explicit); err != nil {
			return "", err
		}

		cfg.APIBaseURL = strings.TrimSuffix(explicit, "/")

		if strings.TrimSpace(cfg.AuthURL) == "" {
			return "", errors.New(
				"safetech: Config.AuthURL is required when Config.APIBaseURL is set: " +
					"/api/ui-config discovery is only available through the gateway",
			)
		}

		return cfg.APIBaseURL, nil
	}

	base := strings.TrimSpace(cfg.BaseURL)
	if base == "" {
		return "", errors.New("safetech: Config.BaseURL or Config.APIBaseURL is required")
	}

	if err := validateBaseURL("Config.BaseURL", base); err != nil {
		return "", err
	}

	cfg.BaseURL = strings.TrimSuffix(base, "/")

	return cfg.BaseURL + "/" + apiPrefix, nil
}

// validateBaseURL reports whether value is an absolute http(s) URL.
func validateBaseURL(field, value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("safetech: parse %s %q: %w", field, value, err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("safetech: %s %q must be an absolute http(s) URL", field, value)
	}

	return nil
}

// buildHTTPClient returns the HTTP client used for all requests, applying
// TLSSkipVerify without mutating the caller's client.
func buildHTTPClient(cfg Config) (*http.Client, error) {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}

	if !cfg.TLSSkipVerify {
		return client, nil
	}

	// Copy the client struct before customising it: the caller's value is
	// left untouched.
	clone := *client

	switch transport := clone.Transport.(type) {
	case nil:
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("safetech: http.DefaultTransport is not an *http.Transport")
		}

		t := defaultTransport.Clone()
		t.TLSClientConfig = insecureTLSConfig(nil)
		clone.Transport = t
	case *http.Transport:
		t := transport.Clone()
		t.TLSClientConfig = insecureTLSConfig(transport.TLSClientConfig)
		clone.Transport = t
	default:
		return nil, fmt.Errorf(
			"safetech: Config.TLSSkipVerify cannot be applied to custom transport %T; configure TLS on it instead",
			clone.Transport,
		)
	}

	return &clone, nil
}

// insecureTLSConfig returns a clone of base with certificate verification
// disabled. The caller opted in by setting Config.TLSSkipVerify.
func insecureTLSConfig(base *tls.Config) *tls.Config {
	var cfg *tls.Config
	if base != nil {
		cfg = base.Clone()
	} else {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	// Config.TLSSkipVerify is an explicit, documented opt-in, which is why the
	// insecure setting is annotated for gosec instead of being enabled silently.
	cfg.InsecureSkipVerify = true // #nosec G402 -- explicit opt-in via Config.TLSSkipVerify

	return cfg
}

// CreateCertificate issues a certificate from a PEM-encoded PKCS#10 request
// using the named CA template.
//
// The request is validated locally before it is sent: the PEM block must decode
// as a certificate request and its self-signature must verify, otherwise an
// error wrapping [ErrInvalidCSR] is returned.
//
// The caller's context bounds the whole operation, including authentication.
func (c *Client) CreateCertificate(
	ctx context.Context,
	csrPEM []byte,
	templateName string,
) (*IssuedCertificate, error) {
	template := strings.TrimSpace(templateName)
	if template == "" {
		return nil, errors.New("safetech: template name is required")
	}

	csr, err := normalizeCSR(csrPEM)
	if err != nil {
		return nil, err
	}

	body := issueRequest{
		Type:           issueTypePKCS10,
		RequestContent: csr,
		TemplateName:   template,
	}

	var payload issuePayload
	if err := c.post(ctx, pathIssue, &body, &payload); err != nil {
		return nil, fmt.Errorf("safetech: issue certificate: %w", err)
	}

	cert, err := certFromIssue(payload, template)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// ListTemplates returns the certificate templates configured in the CA.
//
// Use the Name of a template returned here as the templateName argument of
// [Client.CreateCertificate]. Deleted templates are included so that callers can
// see templates referenced by existing certificates; filter on
// [CertificateTemplate.Deleted] to hide them.
func (c *Client) ListTemplates(ctx context.Context) ([]CertificateTemplate, error) {
	var payload []templatePayload
	if err := c.get(ctx, pathTemplates, &payload); err != nil {
		return nil, fmt.Errorf("safetech: list templates: %w", err)
	}

	templates := make([]CertificateTemplate, 0, len(payload))
	for _, entry := range payload {
		templates = append(templates, entry.template())
	}

	return templates, nil
}

// RevokeOptions tunes [Client.RevokeCertificateWithOptions].
type RevokeOptions struct {
	// AllowAlreadyRevoked reports success instead of [ErrCertificateRevoked]
	// when the certificate is already revoked. Reconciliation loops usually
	// want this, because a retried revocation is not a failure.
	AllowAlreadyRevoked bool
}

// RevokeCertificate revokes the certificate created for the given request id.
//
// The API revokes certificates by serial number, so the serial is resolved from
// the request id through the certificate search endpoint first.
//
// The caller's context bounds the whole operation, including authentication.
func (c *Client) RevokeCertificate(ctx context.Context, certificateID uuid.UUID) error {
	return c.RevokeCertificateWithOptions(ctx, certificateID, RevokeOptions{})
}

// RevokeCertificateWithOptions is [Client.RevokeCertificate] with options.
func (c *Client) RevokeCertificateWithOptions(
	ctx context.Context,
	certificateID uuid.UUID,
	opts RevokeOptions,
) error {
	if certificateID == uuid.Nil() {
		return errors.New("safetech: certificate id is required")
	}

	serial, err := c.findSerialByRequestID(ctx, certificateID)
	if err != nil {
		if opts.AllowAlreadyRevoked && errors.Is(err, ErrCertificateRevoked) {
			return nil
		}

		return err
	}

	body := changeStatusRequest{
		Status: statusRevoked,
		Reason: string(c.cfg.RevokeReason),
	}

	var payload certPayload
	if err := c.patch(ctx, fmt.Sprintf(pathChangeStatus, url.PathEscape(serial)), &body, &payload); err != nil {
		return fmt.Errorf("safetech: revoke certificate %s: %w", serial, err)
	}

	if status := payload.Status; status != "" && status != statusRevoked {
		return fmt.Errorf("safetech: revoke certificate %s: unexpected status %q", serial, status)
	}

	return nil
}

// findSerialByRequestID returns the serial number of the ACTIVE certificate
// issued for the request with the given id.
func (c *Client) findSerialByRequestID(ctx context.Context, id uuid.UUID) (string, error) {
	revoked := false
	seen := 0

	for page := range maxSearchPages {
		req := searchRequest{
			Filters: []searchFilter{{
				Key:       "requestId",
				FieldType: fieldTypeString,
				Operator:  operatorEqual,
				Value:     id.String(),
			}},
			Page: page,
			Size: searchPageSize,
		}

		var payload searchPayload
		if err := c.post(ctx, pathSearch, &req, &payload); err != nil {
			return "", fmt.Errorf("safetech: find certificate %s: %w", id, err)
		}

		if serial, ok := activeSerial(payload.Content); ok {
			return serial, nil
		}

		revoked = revoked || hasStatus(payload.Content, statusRevoked)

		seen += len(payload.Content)
		if len(payload.Content) < searchPageSize || seen >= payload.TotalItems {
			break
		}
	}

	if revoked {
		return "", fmt.Errorf("safetech: find certificate %s: %w", id, ErrCertificateRevoked)
	}

	return "", fmt.Errorf("safetech: find certificate %s: %w", id, ErrCertificateNotFound)
}

// activeSerial returns the serial number of the first ACTIVE certificate that
// carries one.
func activeSerial(certs []certPayload) (string, bool) {
	for _, cert := range certs {
		if cert.Status == statusActive && cert.SerialNumber != "" {
			return cert.SerialNumber, true
		}
	}

	return "", false
}

// hasStatus reports whether any certificate in certs carries the given status.
func hasStatus(certs []certPayload, status string) bool {
	return slices.ContainsFunc(certs, func(cert certPayload) bool {
		return cert.Status == status
	})
}

// pemBytes returns PEM text as bytes, or nil when the CA did not return it.
func pemBytes(value string) []byte {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	return []byte(value)
}

// certFromIssue converts an issue response into a domain certificate.
func certFromIssue(payload issuePayload, templateName string) (*IssuedCertificate, error) {
	info := payload.CertificateInfo

	requestID, err := uuid.Parse(strings.TrimSpace(payload.CertificateRequest.ID))
	if err != nil {
		return nil, fmt.Errorf("safetech: parse request id %q: %w", payload.CertificateRequest.ID, err)
	}

	if strings.TrimSpace(info.PEM) == "" {
		return nil, errors.New("safetech: issue response contains no certificate")
	}

	cert := &IssuedCertificate{
		ID:           requestID,
		SerialNumber: info.SerialNumber,
		PEM:          []byte(info.PEM),
		Chain:        pemBytes(info.Chain),
		FullChain:    pemBytes(info.FullChain),
		Root:         pemBytes(info.Root),
		PKCS7:        pemBytes(info.PKCS7),
		DNHash:       strings.TrimSpace(info.DNHash),
		TemplateName: templateName,
		Status:       info.Status,
	}

	if info.NotBefore != "" {
		if cert.NotBefore, err = parseSTCATime(info.NotBefore); err != nil {
			return nil, err
		}
	}

	if info.NotAfter != "" {
		if cert.NotAfter, err = parseSTCATime(info.NotAfter); err != nil {
			return nil, err
		}
	}

	return cert, nil
}

// stcaTimeLayouts are the timestamp layouts the CA returns. They carry no time
// zone.
var stcaTimeLayouts = [...]string{
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05.999999",
	"2006-01-02T15:04:05",
}

// parseSTCATime parses a timestamp returned by the CA, interpreting it as UTC
// because the API does not report a time zone.
func parseSTCATime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)

	for _, layout := range stcaTimeLayouts {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("safetech: unsupported time format %q", s)
}

// normalizeCSR validates a PEM-encoded PKCS#10 certificate signing request and
// returns it in canonical PEM encoding, which is what the ca-core API expects.
//
// Validation is local so that malformed requests fail before a network round
// trip. The first PEM block of csrPEM must be a certificate request and its
// self-signature must verify.
func normalizeCSR(csrPEM []byte) (string, error) {
	if len(strings.TrimSpace(string(csrPEM))) == 0 {
		return "", fmt.Errorf("%w: request is empty", ErrInvalidCSR)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return "", fmt.Errorf("%w: no PEM block found", ErrInvalidCSR)
	}

	switch block.Type {
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
	default:
		return "", fmt.Errorf("%w: unexpected PEM block %q", ErrInvalidCSR, block.Type)
	}

	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidCSR, err)
	}

	if err := req.CheckSignature(); err != nil {
		return "", fmt.Errorf("%w: signature: %w", ErrInvalidCSR, err)
	}

	encoded := pem.EncodeToMemory(block)
	if encoded == nil {
		return "", fmt.Errorf("%w: cannot encode PEM block", ErrInvalidCSR)
	}

	return string(encoded), nil
}
