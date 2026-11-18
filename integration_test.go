//go:build integration

package safetech_test

import (
	"os"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/edanko/safetech"
	"github.com/edanko/safetech/internal/testutil"
)

// TestIntegrationIssueAndRevoke performs a full round trip against a live CA:
// it issues a certificate from a generated CSR and revokes it again.
//
// The test is skipped unless credentials are provided:
//
//	STCA_BASE_URL=https://ca.example.com:7443 \
//	STCA_REALM_URL=https://keycloak.example.com/realms/ca \
//	STCA_USERNAME=... STCA_PASSWORD=... STCA_TEMPLATE=... \
//	go test -tags=integration -run TestIntegration -v ./...
//
// STCA_REALM_URL is optional: when it is empty the Keycloak endpoint is
// discovered through /api/ui-config. STCA_TEMPLATE is optional and defaults to
// MY_TEMPLATE.
func TestIntegrationIssueAndRevoke(t *testing.T) {
	baseURL := os.Getenv("STCA_BASE_URL")
	username := os.Getenv("STCA_USERNAME")
	password := os.Getenv("STCA_PASSWORD")

	if baseURL == "" || username == "" || password == "" {
		t.Skip("integration credentials not provided; set STCA_BASE_URL, STCA_USERNAME and STCA_PASSWORD")
	}

	template := os.Getenv("STCA_TEMPLATE")
	if template == "" {
		template = "MY_TEMPLATE"
	}

	client, err := safetech.New(safetech.Config{
		BaseURL:       baseURL,
		AuthURL:       os.Getenv("STCA_REALM_URL"),
		Username:      username,
		Password:      password,
		TLSSkipVerify: true, // test environment only
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	csr := testutil.CSR(t, "integration-test.example.com")

	cert, err := client.CreateCertificate(t.Context(), csr, template)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	if cert.ID == uuid.Nil() {
		t.Error("expected a non-nil certificate request id")
	}

	if cert.Status != "ACTIVE" {
		t.Errorf("status = %q, want ACTIVE", cert.Status)
	}

	if cert.SerialNumber == "" {
		t.Error("expected a non-empty serial number")
	}

	if !strings.Contains(string(cert.PEM), "BEGIN CERTIFICATE") {
		t.Error("expected PEM-encoded certificate in the response")
	}

	t.Logf("issued: serial=%s id=%s valid %v..%v",
		cert.SerialNumber, cert.ID, cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))

	if _, err := cert.ParsePEM(); err != nil {
		t.Errorf("ParsePEM: %v", err)
	}

	if err := client.RevokeCertificate(t.Context(), cert.ID); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}

	if err := client.RevokeCertificate(t.Context(), cert.ID); err == nil {
		t.Fatal("expected the second revocation to fail")
	}
}
