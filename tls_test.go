package safetech

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"

	"github.com/edanko/safetech-go/internal/testutil"
)

func TestRootCAsTrustPrivateCA(t *testing.T) {
	t.Parallel()

	ca := testutil.NewCA(t)
	f := newFakeCAWithCertificate(t, ca.ServerCertificate)

	pool, err := RootCAsFromPEM(ca.RootPEM)
	if err != nil {
		t.Fatalf("RootCAsFromPEM: %v", err)
	}

	// Verification stays on: the private root makes the CA's own certificate
	// trustworthy, so TLSSkipVerify is not needed.
	client := f.newClient(t, func(cfg *Config) {
		cfg.RootCAs = pool
	})

	templates, err := client.ListTemplates(t.Context())
	if err != nil {
		t.Fatalf("ListTemplates over verified TLS: %v", err)
	}

	if len(templates) != 2 {
		t.Errorf("templates = %d, want 2", len(templates))
	}
}

func TestWithoutRootCAsVerificationFails(t *testing.T) {
	t.Parallel()

	ca := testutil.NewCA(t)
	f := newFakeCAWithCertificate(t, ca.ServerCertificate)

	// The system trust store does not know this CA, so the handshake must fail.
	client := f.newClient(t)

	if _, err := client.ListTemplates(t.Context()); err == nil {
		t.Fatal("expected TLS verification to fail without the private root")
	} else if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error = %v, want a certificate verification failure", err)
	}
}

func TestRootCAsCannotCombineWithSkipVerify(t *testing.T) {
	t.Parallel()

	pool := x509.NewCertPool()

	_, err := New(Config{
		BaseURL:       "https://ca.example.com:7443",
		RootCAs:       pool,
		TLSSkipVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("New error = %v, want a conflicting-TLS-options failure", err)
	}
}

func TestRootCAsFromPEM(t *testing.T) {
	t.Parallel()

	ca := testutil.NewCA(t)
	second := testutil.NewCA(t)

	tests := map[string]struct {
		pem     []byte
		certs   int
		wantErr string
	}{
		"single certificate": {
			pem:   ca.RootPEM,
			certs: 1,
		},
		"several certificates": {
			pem:   append(append([]byte{}, ca.RootPEM...), second.RootPEM...),
			certs: 2,
		},
		"no certificates": {
			pem:     []byte("this is not PEM"),
			wantErr: "no certificate found",
		},
		"empty input": {
			wantErr: "no certificate found",
		},
		"malformed certificate": {
			pem:     []byte("-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"),
			wantErr: "parse root certificate",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pool, err := RootCAsFromPEM(test.pem)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("RootCAsFromPEM error = %v, want it to contain %q", err, test.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("RootCAsFromPEM: %v", err)
			}

			// A pool built from the CA must actually verify its certificate.
			if got := len(pool.Subjects()); got != test.certs { //nolint:staticcheck // Subjects is the only way to count pool entries
				t.Errorf("pool entries = %d, want %d", got, test.certs)
			}
		})
	}
}

func TestRootCAsDoNotMutateCallerTransport(t *testing.T) {
	t.Parallel()

	ca := testutil.NewCA(t)
	f := newFakeCAWithCertificate(t, ca.ServerCertificate)

	pool, err := RootCAsFromPEM(ca.RootPEM)
	if err != nil {
		t.Fatalf("RootCAsFromPEM: %v", err)
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("http.DefaultTransport is not an *http.Transport")
	}

	transport := base.Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}

	client := f.newClient(t, func(cfg *Config) {
		cfg.RootCAs = pool
		cfg.HTTPClient = &http.Client{Transport: transport}
	})

	if _, err := client.ListTemplates(t.Context()); err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}

	if transport.TLSClientConfig.RootCAs != nil {
		t.Error("RootCAs leaked into the caller's transport")
	}
}

func TestRootCAsRejectOpaqueTransport(t *testing.T) {
	t.Parallel()

	pool := x509.NewCertPool()

	_, err := New(Config{
		BaseURL:    "https://ca.example.com:7443",
		RootCAs:    pool,
		HTTPClient: &http.Client{Transport: opaqueTransport{}},
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be applied to custom transport") {
		t.Fatalf("New error = %v, want a custom-transport failure", err)
	}
}
