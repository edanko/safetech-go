package safetech

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/edanko/safetech-go/internal/testutil"
)

// fastRetry keeps retry tests quick while still exercising the loop.
func fastRetry(cfg *Config) {
	cfg.Retry = RetryPolicy{MaxAttempts: 3, Backoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}
}

// flakyHandler fails with status for the first failures requests, then calls
// next. It reports how many requests it served.
func flakyHandler(status int, failures int32, served *atomic.Int32, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if served.Add(1) <= failures {
			http.Error(w, "transient failure", status)

			return
		}

		next(w, r)
	}
}

func TestAPIBaseURLAddressesCACoreDirectly(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)

	client := f.newClient(t, func(cfg *Config) {
		cfg.BaseURL = ""
		cfg.APIBaseURL = f.server.URL + "/api/v1"
		cfg.AuthURL = f.authURL()
	})

	templates, err := client.ListTemplates(t.Context())
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}

	if len(templates) != 2 {
		t.Errorf("templates = %d, want 2", len(templates))
	}

	if got := len(f.requestsTo(directAPIPath(pathTemplates))); got != 1 {
		t.Errorf("direct template requests = %d, want 1", got)
	}

	if got := len(f.requestsTo(apiPath(pathTemplates))); got != 0 {
		t.Errorf("gateway template requests = %d, want 0", got)
	}

	if got := len(f.requestsTo(uiConfigPath)); got != 0 {
		t.Errorf("ui-config requests = %d, want 0 when AuthURL is explicit", got)
	}
}

func TestNewValidationForAPIBaseURL(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		config Config
		want   string
	}{
		"api base url without auth url": {
			config: Config{APIBaseURL: "http://ca-core.example.com:8081/api/v1"},
			want:   "Config.AuthURL is required",
		},
		"invalid api base url": {
			config: Config{APIBaseURL: "ca-core.example.com:8081", AuthURL: "https://keycloak.example.com/realms/ca"},
			want:   "must be an absolute http(s) URL",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := New(test.config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("New error = %v, want it to contain %q", err, test.want)
			}
		})
	}
}

func TestListTemplatesRetriesTransientFailures(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)

	var served atomic.Int32

	f.setHandler(apiPath(pathTemplates), flakyHandler(
		http.StatusInternalServerError, 2, &served,
		func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"errorCode": 0, "payload": []templatePayload{}})
		},
	))

	client := f.newClient(t, fastRetry)

	if _, err := client.ListTemplates(t.Context()); err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}

	if got := served.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3 (two failures and a success)", got)
	}
}

func TestListTemplatesGivesUpAfterRetries(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)

	var served atomic.Int32

	f.setHandler(apiPath(pathTemplates), flakyHandler(
		http.StatusServiceUnavailable, 5, &served,
		func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"errorCode": 0, "payload": []templatePayload{}})
		},
	))

	client := f.newClient(t, fastRetry)

	if _, err := client.ListTemplates(t.Context()); err == nil {
		t.Fatal("expected an error")
	}

	if got := served.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestRetriesCanBeDisabled(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)

	var served atomic.Int32

	f.setHandler(apiPath(pathTemplates), flakyHandler(
		http.StatusInternalServerError, 2, &served,
		func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"errorCode": 0, "payload": []templatePayload{}})
		},
	))

	client := f.newClient(t, func(cfg *Config) {
		cfg.Retry = RetryPolicy{Disabled: true}
	})

	if _, err := client.ListTemplates(t.Context()); err == nil {
		t.Fatal("expected an error")
	}

	if got := served.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 with retries disabled", got)
	}
}

func TestIssueIsNotRetried(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)

	var served atomic.Int32

	// A failing issue endpoint must never be retried: the CA would issue
	// duplicate certificates.
	f.setHandler(apiPath(pathIssue), func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	client := f.newClient(t, fastRetry)

	if _, err := client.CreateCertificate(t.Context(), testutil.CSR(t, "device.example.com"), testTemplate); err == nil {
		t.Fatal("expected an error")
	}

	if got := served.Load(); got != 1 {
		t.Errorf("issue attempts = %d, want 1", got)
	}
}

func TestRevokeIsNotRetried(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)

	var served atomic.Int32

	f.setHandler(apiPath("/certs/"+testSerial+"/change_status"), func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	client := f.newClient(t, fastRetry)

	if err := client.RevokeCertificate(t.Context(), uuid.MustParse(testRequestID)); err == nil {
		t.Fatal("expected an error")
	}

	if got := served.Load(); got != 1 {
		t.Errorf("revoke attempts = %d, want 1", got)
	}
}

func TestTokenRequestIsRetried(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)

	var served atomic.Int32

	f.setHandler("/realms/", flakyHandler(
		http.StatusInternalServerError, 1, &served,
		func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, tokenResponse{
				AccessToken: testAccessToken,
				ExpiresIn:   3600,
			})
		},
	))

	client := f.newClient(t, fastRetry)

	if _, err := client.ListTemplates(t.Context()); err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}

	if got := served.Load(); got != 2 {
		t.Errorf("token attempts = %d, want 2", got)
	}
}

func TestConcurrentRequestsWaitForOneToken(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)

	var served atomic.Int32

	release := make(chan struct{})

	// The first token request blocks, so the other callers must wait for it
	// instead of starting their own.
	f.setHandler("/realms/", func(w http.ResponseWriter, _ *http.Request) {
		if served.Add(1) == 1 {
			<-release
		}

		writeJSON(w, http.StatusOK, tokenResponse{AccessToken: testAccessToken, ExpiresIn: 3600})
	})

	client := f.newClient(t, fastRetry)

	const callers = 6

	var wg sync.WaitGroup

	errs := make([]error, callers)

	for i := range callers {
		wg.Go(func() {
			_, errs[i] = client.ListTemplates(t.Context())
		})
	}

	// Give the callers time to pile up behind the in-flight request.
	time.Sleep(50 * time.Millisecond)
	close(release)

	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d: %v", i, err)
		}
	}

	if got := served.Load(); got != 1 {
		t.Errorf("token requests = %d, want 1", got)
	}
}

func TestRevokeCertificateWithOptions(t *testing.T) {
	t.Parallel()

	t.Run("already revoked is an error by default", func(t *testing.T) {
		t.Parallel()

		f := newFakeCA(t)
		f.setSearchContent([]certPayload{{Status: statusRevoked, SerialNumber: testSerial}}, 1)

		err := f.newClient(t).RevokeCertificate(t.Context(), uuid.MustParse(testRequestID))
		if !errors.Is(err, ErrCertificateRevoked) {
			t.Errorf("error = %v, want ErrCertificateRevoked", err)
		}
	})

	t.Run("already revoked can be ignored", func(t *testing.T) {
		t.Parallel()

		f := newFakeCA(t)
		f.setSearchContent([]certPayload{{Status: statusRevoked, SerialNumber: testSerial}}, 1)

		err := f.newClient(t).RevokeCertificateWithOptions(
			t.Context(), uuid.MustParse(testRequestID), RevokeOptions{AllowAlreadyRevoked: true},
		)
		if err != nil {
			t.Errorf("error = %v, want nil for an already revoked certificate", err)
		}
	})

	t.Run("missing certificate is still an error", func(t *testing.T) {
		t.Parallel()

		f := newFakeCA(t)
		f.setSearchContent(nil, 0)

		err := f.newClient(t).RevokeCertificateWithOptions(
			t.Context(), uuid.MustParse(testRequestID), RevokeOptions{AllowAlreadyRevoked: true},
		)
		if !errors.Is(err, ErrCertificateNotFound) {
			t.Errorf("error = %v, want ErrCertificateNotFound", err)
		}
	})
}
