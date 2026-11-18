package safetech

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/edanko/safetech-go/internal/testutil"
)

// Fixtures used by the fake CA.
const (
	testRequestID    = "6f9d7e3a-1c2b-4d5e-8f90-112233445566"
	testSerial       = "0A1B2C3D"
	testAccessToken  = "test-access-token"
	testRefreshToken = "test-refresh-token"
	testTemplate     = "MY_TEMPLATE"
	testUsername     = "test-user"
	testPassword     = "test-password"
)

// recordedRequest is one request observed by the fake CA.
type recordedRequest struct {
	method string
	path   string
	header http.Header
	body   []byte
}

// fakeCA is an in-process stand-in for the CA gateway and its Keycloak realm.
// Handlers may be overridden per test to simulate failures. All mutable state
// is guarded by mu so tests stay race-free.
type fakeCA struct {
	server *httptest.Server

	mu             sync.Mutex
	requests       []recordedRequest
	forms          []url.Values
	handlers       map[string]http.HandlerFunc
	expiresIn      int
	rejectRefresh  bool
	searchContent  []certPayload
	searchTotal    int
	revokedStatus  string
	issuePEM       string
	issueChain     string
	issueFullChain string
	issueRoot      string
	issuePKCS7     string
	issueDNHash    string
	certificates   map[string]certPayload
	templates      []templatePayload
}

// newFakeCA starts a fake CA over plain HTTP.
func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()

	return newFakeCAWithTLS(t, false)
}

// newFakeCAWithTLS starts a fake CA, optionally over TLS with a self-signed
// certificate.
func newFakeCAWithTLS(t *testing.T, useTLS bool) *fakeCA {
	t.Helper()

	// One leaf and one chain certificate, so that FullChain is exactly the
	// leaf followed by the chain, as the CA returns it.
	leafPEM := string(testutil.Certificate(t, "issued.example.com"))
	chainPEM := string(testutil.Certificate(t, "chain.example.com"))

	f := &fakeCA{
		handlers:       make(map[string]http.HandlerFunc),
		expiresIn:      3600,
		searchContent:  []certPayload{{Status: statusActive, SerialNumber: testSerial}},
		searchTotal:    1,
		revokedStatus:  statusRevoked,
		issuePEM:       leafPEM,
		issueChain:     chainPEM,
		issueFullChain: leafPEM + chainPEM,
		issueRoot:      string(testutil.Certificate(t, "root.example.com")),
		issuePKCS7:     "-----BEGIN PKCS7-----\nMIIB\n-----END PKCS7-----\n",
		issueDNHash:    "34d96d7243fa893d303396624d32a3d89d3b52a7c3110cc09cc6f4b849049b59",
		certificates: map[string]certPayload{
			testSerial: {
				Status:       statusActive,
				SerialNumber: testSerial,
				PEM:          leafPEM,
				Chain:        chainPEM,
				FullChain:    leafPEM + chainPEM,
				Root:         string(testutil.Certificate(t, "root.example.com")),
				PKCS7:        "-----BEGIN PKCS7-----\nMIIB\n-----END PKCS7-----\n",
				DNHash:       "34d96d7243fa893d303396624d32a3d89d3b52a7c3110cc09cc6f4b849049b59",
				RequestID:    testRequestID,
				TemplateID:   "33333333-3333-4333-8333-333333333333",
				NotBefore:    "2026-10-22T18:28:59.00000",
				NotAfter:     "2027-10-22T18:28:59.00000",
			},
		},
		templates: templateFixtures(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc(uiConfigPath, f.serveUIConfig)
	mux.HandleFunc("/realms/", f.serveToken)
	for _, prefix := range []string{apiPath(""), directAPIPath("")} {
		mux.HandleFunc(prefix+pathIssue, f.serveIssue)
		mux.HandleFunc(prefix+pathSearch, f.serveSearch)
		mux.HandleFunc(prefix+"/certs/", f.serveCerts)
		mux.HandleFunc(prefix+pathTemplates, f.serveTemplates)
	}

	if useTLS {
		f.server = httptest.NewTLSServer(f.record(mux))
	} else {
		f.server = httptest.NewServer(f.record(mux))
	}

	t.Cleanup(f.server.Close)

	return f
}

// newClient returns a Client pointed at the fake CA.
func (f *fakeCA) newClient(t *testing.T, mutate ...func(*Config)) *Client {
	t.Helper()

	cfg := Config{
		BaseURL:  f.server.URL,
		Username: testUsername,
		Password: testPassword,
	}

	for _, apply := range mutate {
		apply(&cfg)
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return client
}

// authURL returns the realm URL the client uses when discovery is skipped.
func (f *fakeCA) authURL() string {
	return f.server.URL + "/realms/ca"
}

// setHandler overrides the handler of the endpoint registered under key.
func (f *fakeCA) setHandler(key string, handler http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.handlers[key] = handler
}

// handler returns the handler registered under key, if any.
func (f *fakeCA) handler(key string) http.HandlerFunc {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.handlers[key]
}

// setSearchContent changes the certificate search response.
func (f *fakeCA) setSearchContent(content []certPayload, total int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.searchContent = content
	f.searchTotal = total
}

// setRevokedStatus changes the status reported by the change_status endpoint.
func (f *fakeCA) setRevokedStatus(status string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.revokedStatus = status
}

// setRejectRefresh makes the token endpoint reject the refresh_token grant.
func (f *fakeCA) setRejectRefresh(reject bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.rejectRefresh = reject
}

// record wraps next, recording every request before it is handled.
func (f *fakeCA) record(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		r.Body = io.NopCloser(bytes.NewReader(body))

		f.mu.Lock()
		f.requests = append(f.requests, recordedRequest{
			method: r.Method,
			path:   r.URL.Path,
			header: r.Header.Clone(),
			body:   body,
		})
		f.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// fixtureDNHash returns the DN hash the fake CA attaches to issued certificates.
func (f *fakeCA) fixtureDNHash() string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.issueDNHash
}

// requestsTo returns the recorded requests whose path matches exactly.
func (f *fakeCA) requestsTo(path string) []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()

	var matched []recordedRequest

	for _, req := range f.requests {
		if req.path == path {
			matched = append(matched, req)
		}
	}

	return matched
}

// tokenForms returns the forms received by the token endpoint.
func (f *fakeCA) tokenForms() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.forms)
}

// apiPath returns the absolute request path of an API endpoint, as the CA
// gateway exposes it under the ca-core prefix.
func apiPath(endpoint string) string {
	return "/" + apiPrefix + endpoint
}

// directAPIPath returns the same path as ca-core exposes it when addressed
// without the gateway.
func directAPIPath(endpoint string) string {
	return "/api/v1" + endpoint
}

// setTemplates changes the template list response.
func (f *fakeCA) setTemplates(templates []templatePayload) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.templates = templates
}

// templateFixtures returns one ST_CA template with a full enrollment context and
// one SCEP template without any context.
func templateFixtures() []templatePayload {
	return []templatePayload{
		{
			ID:                "11111111-1111-4111-8111-111111111111",
			Name:              testTemplate,
			Description:       "template used by the tests",
			OID:               "1.3.6.1.4.1.311.21.8.1",
			ProtocolType:      string(TemplateProtocolSTCA),
			MaxValidityPeriod: 365,
			MinKeySize:        2048,
			KeyUsages:         160,
			Context: &templateContextPayload{
				STCAEnrollment: &stcaEnrollmentPayload{
					EnrollmentScenario:              "STANDARD",
					CryptoTypes:                     []string{"RSA"},
					KeySizes:                        []int{2048, 4096},
					SignatureAlgorithms:             []string{"SHA256WITHRSA"},
					RequiredSubjectAlternativeNames: []string{"UPN"},
					IncludeSID:                      true,
					SupportedToken:                  "RUTOKEN",
					InstallRutokenConfig:            true,
				},
				Common: &commonContextPayload{
					CheckUniquePublicKeys:  true,
					ApplyKeyUsages:         true,
					ApplyExtendedKeyUsages: true,
				},
			},
		},
		{
			ID:                "22222222-2222-4222-8222-222222222222",
			Name:              "scep-fixture",
			Description:       "SCEP template without context",
			ProtocolType:      string(TemplateProtocolSCEP),
			MaxValidityPeriod: 30,
			MinKeySize:        1024,
			KeyUsages:         1,
		},
	}
}

// writeJSON writes body as a JSON response.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeCA) serveUIConfig(w http.ResponseWriter, r *http.Request) {
	if handler := f.handler(uiConfigPath); handler != nil {
		handler(w, r)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"keyCloak": map[string]any{
			"config": map[string]any{
				"url":      f.server.URL,
				"realm":    "ca",
				"clientId": defaultClientID,
			},
		},
	})
}

func (f *fakeCA) serveToken(w http.ResponseWriter, r *http.Request) {
	if handler := f.handler("/realms/"); handler != nil {
		handler(w, r)

		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	f.mu.Lock()
	f.forms = append(f.forms, r.PostForm)
	expiresIn, rejectRefresh := f.expiresIn, f.rejectRefresh
	f.mu.Unlock()

	if r.PostForm.Get("grant_type") == "refresh_token" && rejectRefresh {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})

		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  testAccessToken,
		ExpiresIn:    expiresIn,
		RefreshToken: testRefreshToken,
	})
}

func (f *fakeCA) serveIssue(w http.ResponseWriter, r *http.Request) {
	if handler := f.handler(r.URL.Path); handler != nil {
		handler(w, r)

		return
	}

	var req issueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	f.mu.Lock()
	pemText, chain, fullChain, root, pkcs7, dnHash := f.issuePEM, f.issueChain, f.issueFullChain, f.issueRoot, f.issuePKCS7, f.issueDNHash
	f.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"errorCode":    0,
		"errorMessage": "",
		"payload": issuePayload{
			CertificateInfo: certPayload{
				Status:       statusActive,
				SerialNumber: testSerial,
				PEM:          pemText,
				Chain:        chain,
				FullChain:    fullChain,
				Root:         root,
				PKCS7:        pkcs7,
				DNHash:       dnHash,
				NotBefore:    "2026-10-22T18:28:59.00000",
				NotAfter:     "2027-10-22T18:28:59.00000",
			},
			CertificateRequest: reqPayload{ID: testRequestID, Status: "APPROVED"},
		},
	})
}

func (f *fakeCA) serveSearch(w http.ResponseWriter, r *http.Request) {
	if handler := f.handler(r.URL.Path); handler != nil {
		handler(w, r)

		return
	}

	f.mu.Lock()
	content, total := f.searchContent, f.searchTotal
	f.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"errorCode": 0,
		"payload":   searchPayload{Content: content, TotalItems: total},
	})
}

func (f *fakeCA) serveTemplates(w http.ResponseWriter, r *http.Request) {
	if handler := f.handler(r.URL.Path); handler != nil {
		handler(w, r)

		return
	}

	f.mu.Lock()
	templates := f.templates
	f.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"errorCode": 0,
		"payload":   templates,
	})
}

// serveCerts dispatches certificate requests: a PATCH or a /change_status suffix
// changes the status, anything else reads a certificate by serial.
func (f *fakeCA) serveCerts(w http.ResponseWriter, r *http.Request) {
	if handler := f.handler(r.URL.Path); handler != nil {
		handler(w, r)

		return
	}

	if strings.HasSuffix(r.URL.Path, "/change_status") {
		f.serveChangeStatus(w, r)

		return
	}

	f.serveCertificate(w, r)
}

// serveCertificate answers GET /certs/{serial}.
func (f *fakeCA) serveCertificate(w http.ResponseWriter, r *http.Request) {
	serial := ""
	if _, after, ok := strings.Cut(r.URL.Path, "/certs/"); ok {
		serial, _, _ = strings.Cut(after, "/")
	}

	f.mu.Lock()
	payload, found := f.certificates[serial]
	f.mu.Unlock()

	if !found {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"errorCode":    104,
			"errorMessage": "Certificate with serial number " + serial + " not found",
		})

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"errorCode": 0, "payload": payload})
}

// setCertificate replaces the certificate the fake CA serves for serial.
func (f *fakeCA) setCertificate(serial string, payload certPayload) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.certificates[serial] = payload
}

// removeCertificate drops a certificate so the CA reports it as missing.
func (f *fakeCA) removeCertificate(serial string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.certificates, serial)
}

func (f *fakeCA) serveChangeStatus(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	status := f.revokedStatus
	f.mu.Unlock()

	serial := ""
	if _, after, ok := strings.Cut(r.URL.Path, "/certs/"); ok {
		serial, _, _ = strings.Cut(after, "/change_status")
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"errorCode": 0,
		"payload":   certPayload{Status: status, SerialNumber: serial},
	})
}
