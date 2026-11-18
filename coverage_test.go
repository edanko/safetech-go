package safetech

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/edanko/safetech/internal/testutil"
)

func TestDiscoveryDecodeFailure(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	f.setHandler(uiConfigPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	})

	_, err := f.newClient(t).accessToken(t.Context())
	if err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("error = %v, want a decode failure", err)
	}
}

func TestTokenResponseMalformedJSON(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	f.setHandler("/realms/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("<html>gateway error</html>"))
	})

	_, err := f.newClient(t).accessToken(t.Context())
	if err == nil || !strings.Contains(err.Error(), "decode token response") {
		t.Fatalf("error = %v, want a decode failure", err)
	}
}

func TestTokenResponseWithoutAccessToken(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	f.setHandler("/realms/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"token_type": "Bearer", "expires_in": 300})
	})

	_, err := f.newClient(t).accessToken(t.Context())
	if err == nil || !strings.Contains(err.Error(), "no access_token") {
		t.Fatalf("error = %v, want a missing-token failure", err)
	}
}

func TestErrorFormatting(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		want string
	}{
		"api error with code": {
			err:  &APIError{Code: 5, Message: "denied"},
			want: "safetech: api error 5: denied",
		},
		"api error without code": {
			err:  &APIError{Message: "denied"},
			want: "safetech: api error: denied",
		},
		"http error with body": {
			err:  &HTTPError{StatusCode: 502, Body: "bad gateway"},
			want: "safetech: http 502: bad gateway",
		},
		"http error without body": {
			err:  &HTTPError{StatusCode: 503},
			want: "safetech: http 503",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := test.err.Error(); got != test.want {
				t.Errorf("Error() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestNewRejectsUnparseableURL(t *testing.T) {
	t.Parallel()

	// A non-numeric port makes url.Parse fail, which is distinct from a
	// relative URL.
	_, err := New(Config{BaseURL: "https://ca.example.com:not-a-port"})
	if err == nil || !strings.Contains(err.Error(), "parse Config.BaseURL") {
		t.Fatalf("error = %v, want a URL parse failure", err)
	}
}

func TestTLSSkipVerifyClonesCallerTLSSettings(t *testing.T) {
	t.Parallel()

	f := newFakeCAWithTLS(t, true)

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("http.DefaultTransport is not an *http.Transport")
	}

	transport := base.Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}

	client := f.newClient(t, func(cfg *Config) {
		cfg.AuthURL = f.authURL()
		cfg.TLSSkipVerify = true
		cfg.HTTPClient = &http.Client{Transport: transport}
	})

	if _, err := client.ListTemplates(t.Context()); err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}

	// The caller's transport must keep verifying certificates.
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("TLSSkipVerify mutated the caller's transport")
	}
}

func TestCreateCertificateWithoutPEM(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	f.setHandler(apiPath(pathIssue), func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"errorCode": 0,
			"payload": issuePayload{
				CertificateInfo: certPayload{
					Status:       statusActive,
					SerialNumber: testSerial,
				},
				CertificateRequest: reqPayload{ID: testRequestID},
			},
		})
	})

	_, err := f.newClient(t).CreateCertificate(t.Context(), testutil.CSR(t, "device.example.com"), testTemplate)
	if err == nil || !strings.Contains(err.Error(), "contains no certificate") {
		t.Fatalf("error = %v, want a missing-certificate failure", err)
	}
}

func TestSearchStopsAtMaxPages(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)

	// A full page of irrelevant certificates, with a total that implies more
	// pages, so the lookup must give up after maxSearchPages.
	f.setHandler(apiPath(pathSearch), func(w http.ResponseWriter, _ *http.Request) {
		content := make([]certPayload, searchPageSize)
		for i := range content {
			content[i] = certPayload{Status: "PENDING", SerialNumber: "FF"}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"errorCode": 0,
			"payload":   searchPayload{Content: content, TotalItems: searchPageSize * 100},
		})
	})

	err := f.newClient(t).RevokeCertificate(t.Context(), uuid.MustParse(testRequestID))
	if !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("error = %v, want ErrCertificateNotFound", err)
	}

	if got := len(f.requestsTo(apiPath(pathSearch))); got != maxSearchPages {
		t.Errorf("search requests = %d, want %d", got, maxSearchPages)
	}
}

func TestAccessTokenWaiterStopsWhenContextIsCanceled(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)

	entered := make(chan struct{})
	release := make(chan struct{})

	var once sync.Once

	// The first token request blocks so that a second caller has to wait.
	f.setHandler("/realms/", func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(entered) })
		<-release

		writeJSON(w, http.StatusOK, tokenResponse{AccessToken: testAccessToken, ExpiresIn: 3600})
	})

	client := f.newClient(t)

	var wg sync.WaitGroup

	wg.Go(func() {
		_, _ = client.ListTemplates(t.Context())
	})

	<-entered

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := client.accessToken(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}

	close(release)
	wg.Wait()
}

func TestRetryableGivesUpWhenContextExpiresDuringBackoff(t *testing.T) {
	t.Parallel()

	client := &Client{retry: retryPolicy{
		maxAttempts: 3,
		backoff:     200 * time.Millisecond,
		maxBackoff:  200 * time.Millisecond,
	}}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()

	err := client.retryable(ctx, "operation", func() error {
		return &HTTPError{StatusCode: http.StatusServiceUnavailable}
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
}

func TestDecodeEnvelopeRejectsWrongPayloadType(t *testing.T) {
	t.Parallel()

	var out []templatePayload

	err := decodeEnvelope([]byte(`{"errorCode":0,"payload":{"not":"an array"}}`), &out)
	if err == nil || !strings.Contains(err.Error(), "decode response payload") {
		t.Fatalf("error = %v, want a payload decode failure", err)
	}
}
