package safetech

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/edanko/safetech/internal/testutil"
)

func TestNewAppliesDefaults(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	client := f.newClient(t)

	if client.node != defaultNode {
		t.Errorf("node = %q, want %q", client.node, defaultNode)
	}

	if client.cfg.RevokeReason != RevokeReasonUnspecified {
		t.Errorf("revoke reason = %q, want %q", client.cfg.RevokeReason, RevokeReasonUnspecified)
	}

	if want := "safetech/" + Version; client.userAgent != want {
		t.Errorf("user agent = %q, want %q", client.userAgent, want)
	}

	if want := f.server.URL + "/" + apiPrefix; client.apiBase != want {
		t.Errorf("apiBase = %q, want %q", client.apiBase, want)
	}
}

func TestNewValidation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		config Config
		want   string
	}{
		"missing base url": {
			config: Config{},
			want:   "Config.BaseURL is required",
		},
		"relative base url": {
			config: Config{BaseURL: "ca.example.com:7443"},
			want:   "must be an absolute http(s) URL",
		},
		"unsupported scheme": {
			config: Config{BaseURL: "ftp://ca.example.com"},
			want:   "must be an absolute http(s) URL",
		},
		"tls skip verify with opaque transport": {
			config: Config{
				BaseURL:       "https://ca.example.com",
				TLSSkipVerify: true,
				HTTPClient:    &http.Client{Transport: opaqueTransport{}},
			},
			want: "cannot be applied to custom transport",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := New(test.config)
			if err == nil {
				t.Fatalf("New(%+v) = nil error, want %q", test.config, test.want)
			}

			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("New error = %q, want it to contain %q", err, test.want)
			}
		})
	}
}

// opaqueTransport is a RoundTripper that cannot carry a custom TLS config.
type opaqueTransport struct{}

func (opaqueTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("opaqueTransport: not implemented")
}

func TestCreateCertificate(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	client := f.newClient(t)

	cert, err := client.CreateCertificate(t.Context(), testutil.CSR(t, "device.example.com"), testTemplate)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	if want := uuid.MustParse(testRequestID); cert.ID != want {
		t.Errorf("ID = %v, want %v", cert.ID, want)
	}

	if cert.SerialNumber != testSerial {
		t.Errorf("SerialNumber = %q, want %q", cert.SerialNumber, testSerial)
	}

	if cert.Status != statusActive {
		t.Errorf("Status = %q, want %q", cert.Status, statusActive)
	}

	if cert.TemplateName != testTemplate {
		t.Errorf("TemplateName = %q, want %q", cert.TemplateName, testTemplate)
	}

	if len(cert.PEM) == 0 {
		t.Error("PEM is empty")
	}

	wantNotBefore := time.Date(2026, time.October, 22, 18, 28, 59, 0, time.UTC)
	if !cert.NotBefore.Equal(wantNotBefore) {
		t.Errorf("NotBefore = %v, want %v", cert.NotBefore, wantNotBefore)
	}

	if !cert.NotAfter.After(cert.NotBefore) {
		t.Errorf("NotAfter = %v, want it to be after NotBefore %v", cert.NotAfter, cert.NotBefore)
	}

	requests := f.requestsTo(apiPath(pathIssue))
	if len(requests) != 1 {
		t.Fatalf("issue requests = %d, want 1", len(requests))
	}

	issued := requests[0]

	if got, want := issued.header.Get("Authorization"), "Bearer "+testAccessToken; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}

	if got := issued.header.Get("x-eureka-node"); got != defaultNode {
		t.Errorf("x-eureka-node = %q, want %q", got, defaultNode)
	}

	if got := issued.header.Get("User-Agent"); !strings.HasPrefix(got, "safetech/") {
		t.Errorf("User-Agent = %q, want the safetech prefix", got)
	}

	if got := issued.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var sent issueRequest
	if err := json.Unmarshal(issued.body, &sent); err != nil {
		t.Fatalf("decode issue request: %v", err)
	}

	if sent.Type != issueTypePKCS10 {
		t.Errorf("type = %q, want %q", sent.Type, issueTypePKCS10)
	}

	if sent.TemplateName != testTemplate {
		t.Errorf("templateName = %q, want %q", sent.TemplateName, testTemplate)
	}

	block, rest := pem.Decode([]byte(sent.RequestContent))
	if block == nil {
		t.Fatal("request_content is not PEM-encoded")
	}

	if block.Type != "CERTIFICATE REQUEST" {
		t.Errorf("request_content block type = %q, want CERTIFICATE REQUEST", block.Type)
	}

	if len(bytes.TrimSpace(rest)) != 0 {
		t.Errorf("request_content has data after the first PEM block: %q", rest)
	}

	if !bytes.HasSuffix([]byte(sent.RequestContent), []byte("-----END CERTIFICATE REQUEST-----\n")) {
		t.Error("request_content does not end with a newline")
	}
}

func TestCreateCertificateRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	client := f.newClient(t)

	validCSR := testutil.CSR(t, "device.example.com")

	block, _ := pem.Decode(validCSR)
	if block == nil {
		t.Fatal("test fixture is not PEM-encoded")
	}

	tampered := *block

	tampered.Bytes = slices.Clone(block.Bytes)
	tampered.Bytes[len(tampered.Bytes)-1] ^= 0xFF

	certificateBlock, _ := pem.Decode(testutil.Certificate(t, "device.example.com"))
	if certificateBlock == nil {
		t.Fatal("certificate fixture is not PEM-encoded")
	}

	tests := map[string]struct {
		csr      []byte
		template string
		want     string
		invalid  bool
	}{
		"empty csr": {
			template: testTemplate,
			want:     ErrInvalidCSR.Error(),
			invalid:  true,
		},
		"whitespace csr": {
			csr:      []byte("  \n\t "),
			template: testTemplate,
			want:     ErrInvalidCSR.Error(),
			invalid:  true,
		},
		"not pem": {
			csr:      []byte("this is not a certificate request"),
			template: testTemplate,
			want:     "no PEM block found",
			invalid:  true,
		},
		"wrong block type": {
			csr:      pem.EncodeToMemory(certificateBlock),
			template: testTemplate,
			want:     "unexpected PEM block",
			invalid:  true,
		},
		"tampered signature": {
			csr:      pem.EncodeToMemory(&tampered),
			template: testTemplate,
			want:     "signature",
			invalid:  true,
		},
		"missing template": {
			csr:      validCSR,
			template: "   ",
			want:     "template name is required",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := client.CreateCertificate(t.Context(), test.csr, test.template)
			if err == nil {
				t.Fatalf("CreateCertificate(%q) = nil error, want %q", name, test.want)
			}

			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q, want it to contain %q", err, test.want)
			}

			if test.invalid && !errors.Is(err, ErrInvalidCSR) {
				t.Errorf("error = %v, want it to wrap ErrInvalidCSR", err)
			}
		})
	}

	if got := len(f.requestsTo(apiPath(pathIssue))); got != 0 {
		t.Errorf("issue requests = %d, want 0: invalid input must not reach the API", got)
	}
}

func TestCreateCertificateAPIError(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	f.setHandler(apiPath(pathIssue), func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"errorCode":    42,
			"errorMessage": "template not found",
		})
	})

	_, err := f.newClient(t).CreateCertificate(
		t.Context(), testutil.CSR(t, "device.example.com"), testTemplate,
	)
	if err == nil {
		t.Fatal("expected an error")
	}

	apiErr, ok := errors.AsType[*APIError](err)
	if !ok {
		t.Fatalf("error = %v, want an *APIError", err)
	}

	if apiErr.Code != 42 {
		t.Errorf("Code = %d, want 42", apiErr.Code)
	}

	if apiErr.Message != "template not found" {
		t.Errorf("Message = %q, want %q", apiErr.Message, "template not found")
	}
}

func TestCreateCertificateHTTPError(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	f.setHandler(apiPath(pathIssue), func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gateway unavailable", http.StatusBadGateway)
	})

	_, err := f.newClient(t).CreateCertificate(
		t.Context(), testutil.CSR(t, "device.example.com"), testTemplate,
	)
	if err == nil {
		t.Fatal("expected an error")
	}

	httpErr, ok := errors.AsType[*HTTPError](err)
	if !ok {
		t.Fatalf("error = %v, want an *HTTPError", err)
	}

	if httpErr.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode = %d, want %d", httpErr.StatusCode, http.StatusBadGateway)
	}

	if !strings.Contains(httpErr.Body, "gateway unavailable") {
		t.Errorf("Body = %q, want it to contain the response text", httpErr.Body)
	}
}

func TestRevokeCertificate(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	client := f.newClient(t, func(cfg *Config) {
		cfg.RevokeReason = RevokeReasonKeyCompromise
	})

	if err := client.RevokeCertificate(t.Context(), uuid.MustParse(testRequestID)); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}

	searchRequests := f.requestsTo(apiPath(pathSearch))
	if len(searchRequests) != 1 {
		t.Fatalf("search requests = %d, want 1", len(searchRequests))
	}

	var search searchRequest
	if err := json.Unmarshal(searchRequests[0].body, &search); err != nil {
		t.Fatalf("decode search request: %v", err)
	}

	if len(search.Filters) != 1 || search.Filters[0].Value != testRequestID {
		t.Errorf("search filters = %+v, want one requestId filter for %s", search.Filters, testRequestID)
	}

	statusRequests := f.requestsTo(apiPath("/certs/" + testSerial + "/change_status"))
	if len(statusRequests) != 1 {
		t.Fatalf("change_status requests = %d, want 1", len(statusRequests))
	}

	if got := statusRequests[0].method; got != http.MethodPatch {
		t.Errorf("change_status method = %q, want PATCH", got)
	}

	var change changeStatusRequest
	if err := json.Unmarshal(statusRequests[0].body, &change); err != nil {
		t.Fatalf("decode change_status request: %v", err)
	}

	if change.Status != statusRevoked {
		t.Errorf("status = %q, want %q", change.Status, statusRevoked)
	}

	if want := string(RevokeReasonKeyCompromise); change.Reason != want {
		t.Errorf("reason = %q, want %q", change.Reason, want)
	}
}

func TestRevokeCertificateErrors(t *testing.T) {
	t.Parallel()

	t.Run("already revoked", func(t *testing.T) {
		t.Parallel()

		f := newFakeCA(t)
		f.setSearchContent([]certPayload{{Status: statusRevoked, SerialNumber: testSerial}}, 1)

		err := f.newClient(t).RevokeCertificate(t.Context(), uuid.MustParse(testRequestID))
		if !errors.Is(err, ErrCertificateRevoked) {
			t.Errorf("error = %v, want it to wrap ErrCertificateRevoked", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		t.Parallel()

		f := newFakeCA(t)
		f.setSearchContent(nil, 0)

		err := f.newClient(t).RevokeCertificate(t.Context(), uuid.MustParse(testRequestID))
		if !errors.Is(err, ErrCertificateNotFound) {
			t.Errorf("error = %v, want it to wrap ErrCertificateNotFound", err)
		}
	})

	t.Run("nil id", func(t *testing.T) {
		t.Parallel()

		f := newFakeCA(t)

		err := f.newClient(t).RevokeCertificate(t.Context(), uuid.Nil())
		if err == nil || !strings.Contains(err.Error(), "certificate id is required") {
			t.Errorf("error = %v, want it to report a missing certificate id", err)
		}
	})

	t.Run("unexpected status", func(t *testing.T) {
		t.Parallel()

		f := newFakeCA(t)
		f.setRevokedStatus(statusActive)

		err := f.newClient(t).RevokeCertificate(t.Context(), uuid.MustParse(testRequestID))
		if err == nil || !strings.Contains(err.Error(), "unexpected status") {
			t.Errorf("error = %v, want it to report an unexpected status", err)
		}
	})
}

func TestRevokeCertificatePaginatesSearch(t *testing.T) {
	t.Parallel()

	const pending = 100

	f := newFakeCA(t)
	f.setHandler(apiPath(pathSearch), func(w http.ResponseWriter, r *http.Request) {
		var req searchRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		content := make([]certPayload, pending)
		for i := range content {
			content[i] = certPayload{Status: "PENDING", SerialNumber: "FF"}
		}

		payload := searchPayload{Content: content, TotalItems: pending + 1}

		if req.Page > 0 {
			payload.Content = []certPayload{{Status: statusActive, SerialNumber: testSerial}}
		}

		writeJSON(w, http.StatusOK, map[string]any{"errorCode": 0, "payload": payload})
	})

	if err := f.newClient(t).RevokeCertificate(t.Context(), uuid.MustParse(testRequestID)); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}

	if got := len(f.requestsTo(apiPath("/certs/" + testSerial + "/change_status"))); got != 1 {
		t.Errorf("change_status requests = %d, want 1: the active certificate is on the second page", got)
	}
}

func TestConcurrentRequestsShareOneToken(t *testing.T) {
	t.Parallel()

	const calls = 8

	f := newFakeCA(t)
	client := f.newClient(t)
	csr := testutil.CSR(t, "device.example.com")

	var wg sync.WaitGroup

	errs := make([]error, calls)

	for i := range calls {
		wg.Go(func() {
			_, errs[i] = client.CreateCertificate(t.Context(), csr, testTemplate)
		})
	}

	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("call %d: %v", i, err)
		}
	}

	passwordGrants := 0

	for _, form := range f.tokenForms() {
		if form.Get("grant_type") == "password" {
			passwordGrants++
		}
	}

	if passwordGrants != 1 {
		t.Errorf("password grant requests = %d, want 1: the token must be cached", passwordGrants)
	}
}

func TestTLSSkipVerify(t *testing.T) {
	t.Parallel()

	f := newFakeCAWithTLS(t, true)
	csr := testutil.CSR(t, "device.example.com")

	t.Run("verification rejects self-signed certificate", func(t *testing.T) {
		t.Parallel()

		client := f.newClient(t, func(cfg *Config) {
			cfg.AuthURL = f.authURL()
		})

		if _, err := client.CreateCertificate(t.Context(), csr, testTemplate); err == nil {
			t.Fatal("expected the self-signed certificate to be rejected")
		}
	})

	t.Run("opt-in disables verification", func(t *testing.T) {
		t.Parallel()

		client := f.newClient(t, func(cfg *Config) {
			cfg.AuthURL = f.authURL()
			cfg.TLSSkipVerify = true
		})

		if _, err := client.CreateCertificate(t.Context(), csr, testTemplate); err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
	})
}

func TestUserCertificateParsePEM(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		pem     []byte
		wantErr string
	}{
		"valid": {
			pem: testutil.Certificate(t, "leaf.example.com"),
		},
		"empty": {
			wantErr: "certificate PEM is empty",
		},
		"no pem block": {
			pem:     []byte("not pem"),
			wantErr: "no PEM block",
		},
		"invalid der": {
			pem:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("nope")}),
			wantErr: "parse certificate",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			parsed, err := (&UserCertificate{PEM: test.pem}).ParsePEM()
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("ParsePEM error = %v, want it to contain %q", err, test.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("ParsePEM: %v", err)
			}

			if got := parsed.Subject.CommonName; got != "leaf.example.com" {
				t.Errorf("CommonName = %q, want %q", got, "leaf.example.com")
			}
		})
	}
}

func TestListTemplates(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)

	templates, err := f.newClient(t).ListTemplates(t.Context())
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}

	if len(templates) != 2 {
		t.Fatalf("templates = %d, want 2", len(templates))
	}

	stca := templates[0]

	if stca.Name != testTemplate {
		t.Errorf("Name = %q, want %q", stca.Name, testTemplate)
	}

	if stca.ID != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("ID = %q, want the fixture id", stca.ID)
	}

	if stca.ProtocolType != TemplateProtocolSTCA {
		t.Errorf("ProtocolType = %q, want %q", stca.ProtocolType, TemplateProtocolSTCA)
	}

	if stca.MaxValidityPeriod != 365 {
		t.Errorf("MaxValidityPeriod = %d, want 365", stca.MaxValidityPeriod)
	}

	if stca.MinKeySize != 2048 {
		t.Errorf("MinKeySize = %d, want 2048", stca.MinKeySize)
	}

	if stca.KeyUsages != 160 {
		t.Errorf("KeyUsages = %d, want 160", stca.KeyUsages)
	}

	if stca.Deleted {
		t.Error("Deleted = true, want false")
	}

	enrollment := stca.Context.STCAEnrollment
	if enrollment == nil {
		t.Fatal("STCAEnrollment context is nil")
	}

	if enrollment.EnrollmentScenario != "STANDARD" {
		t.Errorf("EnrollmentScenario = %q, want STANDARD", enrollment.EnrollmentScenario)
	}

	if want := []int{2048, 4096}; !slices.Equal(enrollment.KeySizes, want) {
		t.Errorf("KeySizes = %v, want %v", enrollment.KeySizes, want)
	}

	if !enrollment.IncludeSID {
		t.Error("IncludeSID = false, want true")
	}

	if enrollment.SupportedToken != "RUTOKEN" {
		t.Errorf("SupportedToken = %q, want RUTOKEN", enrollment.SupportedToken)
	}

	common := stca.Context.Common
	if common == nil {
		t.Fatal("Common context is nil")
	}

	if !common.CheckUniquePublicKeys || !common.ApplyKeyUsages || !common.ApplyExtendedKeyUsages {
		t.Errorf("common context = %+v, want every flag true", *common)
	}

	scep := templates[1]
	if scep.ProtocolType != TemplateProtocolSCEP {
		t.Errorf("ProtocolType = %q, want %q", scep.ProtocolType, TemplateProtocolSCEP)
	}

	if scep.Context.STCAEnrollment != nil || scep.Context.Common != nil {
		t.Errorf("SCEP template context = %+v, want empty", scep.Context)
	}

	requests := f.requestsTo(apiPath(pathTemplates))
	if len(requests) != 1 {
		t.Fatalf("template requests = %d, want 1", len(requests))
	}

	if got := requests[0].method; got != http.MethodGet {
		t.Errorf("method = %q, want GET", got)
	}

	if got, want := requests[0].header.Get("Authorization"), "Bearer "+testAccessToken; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

func TestListTemplatesEmpty(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	f.setTemplates(nil)

	templates, err := f.newClient(t).ListTemplates(t.Context())
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}

	if templates == nil {
		t.Error("templates = nil, want an empty slice")
	}

	if len(templates) != 0 {
		t.Errorf("templates = %d, want 0", len(templates))
	}
}

func TestListTemplatesErrors(t *testing.T) {
	t.Parallel()

	t.Run("api error", func(t *testing.T) {
		t.Parallel()

		f := newFakeCA(t)
		f.setHandler(apiPath(pathTemplates), func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"errorCode":    23,
				"errorMessage": "access denied",
			})
		})

		_, err := f.newClient(t).ListTemplates(t.Context())
		if err == nil {
			t.Fatal("expected an error")
		}

		apiErr, ok := errors.AsType[*APIError](err)
		if !ok {
			t.Fatalf("error = %v, want an *APIError", err)
		}

		if apiErr.Code != 23 {
			t.Errorf("Code = %d, want 23", apiErr.Code)
		}
	})

	t.Run("http error", func(t *testing.T) {
		t.Parallel()

		f := newFakeCA(t)
		f.setHandler(apiPath(pathTemplates), func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		})

		_, err := f.newClient(t).ListTemplates(t.Context())
		if err == nil {
			t.Fatal("expected an error")
		}

		httpErr, ok := errors.AsType[*HTTPError](err)
		if !ok {
			t.Fatalf("error = %v, want an *HTTPError", err)
		}

		if httpErr.StatusCode != http.StatusInternalServerError {
			t.Errorf("StatusCode = %d, want 500", httpErr.StatusCode)
		}
	})
}
