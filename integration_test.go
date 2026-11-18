//go:build integration

package safetech_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/edanko/safetech-go"
	"github.com/edanko/safetech-go/internal/testutil"
)

// integrationClient returns a client configured from the environment, or skips
// the test when credentials are missing.
//
//	STCA_BASE_URL=https://ca.example.com:7443 \
//	STCA_REALM_URL=https://keycloak.example.com/realms/ca \
//	STCA_USERNAME=... STCA_PASSWORD=... \
//	go test -tags=integration -run TestIntegration -v ./...
//
// STCA_REALM_URL is optional: when it is empty the Keycloak endpoint is
// discovered through /api/ui-config.
func integrationClient(t *testing.T) *safetech.Client {
	t.Helper()

	baseURL := os.Getenv("STCA_BASE_URL")
	username := os.Getenv("STCA_USERNAME")
	password := os.Getenv("STCA_PASSWORD")

	if baseURL == "" || username == "" || password == "" {
		t.Skip("integration credentials not provided; set STCA_BASE_URL, STCA_USERNAME and STCA_PASSWORD")
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

	return client
}

// TestIntegrationListTemplates lists the CA templates and verifies that the
// template named by STCA_TEMPLATE, when set, is present.
func TestIntegrationListTemplates(t *testing.T) {
	client := integrationClient(t)

	templates, err := client.ListTemplates(t.Context())
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}

	if len(templates) == 0 {
		t.Fatal("no templates returned")
	}

	byProtocol := map[safetech.TemplateProtocol]int{}

	for _, template := range templates {
		byProtocol[template.ProtocolType]++

		if template.Name == "" || template.ID == "" {
			t.Errorf("template %+v has an empty name or id", template)
		}
	}

	t.Logf("templates: %d (%v)", len(templates), byProtocol)

	want := os.Getenv("STCA_TEMPLATE")
	if want == "" {
		return
	}

	for _, template := range templates {
		if template.Name == want {
			t.Logf("template %q: protocol=%s scenario=%v keySizes=%v",
				template.Name, template.ProtocolType,
				scenario(template), keySizes(template))

			return
		}
	}

	t.Errorf("template %q not found in the CA template list", want)
}

// scenario returns the ST_CA enrollment scenario of a template, if any.
func scenario(template safetech.CertificateTemplate) string {
	if template.Context.STCAEnrollment == nil {
		return ""
	}

	return template.Context.STCAEnrollment.EnrollmentScenario
}

// keySizes returns the accepted key sizes of a template, if reported.
func keySizes(template safetech.CertificateTemplate) []int {
	if template.Context.STCAEnrollment == nil {
		return nil
	}

	return template.Context.STCAEnrollment.KeySizes
}

// usableTemplate returns the template to issue with: STCA_TEMPLATE when set,
// otherwise the first ST_CA template whose enrollment scenario is STANDARD
// (the only scenario the CA accepts for API issuance).
func usableTemplate(t *testing.T, client *safetech.Client) string {
	t.Helper()

	if name := os.Getenv("STCA_TEMPLATE"); name != "" {
		return name
	}

	templates, err := client.ListTemplates(t.Context())
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}

	for _, template := range templates {
		if template.Deleted || template.ProtocolType != safetech.TemplateProtocolSTCA {
			continue
		}

		if scenario(template) == "STANDARD" {
			return template.Name
		}
	}

	t.Skip("no ST_CA template with a STANDARD enrollment scenario found; set STCA_TEMPLATE")

	return ""
}

// TestIntegrationIssueAndRevoke performs a full round trip against a live CA:
// it issues a certificate from a generated CSR and revokes it again.
func TestIntegrationIssueAndRevoke(t *testing.T) {
	client := integrationClient(t)
	template := usableTemplate(t, client)

	csr := testutil.CSR(t, "integration-test.example.com")

	cert, err := client.CreateCertificate(t.Context(), csr, template)
	if err != nil {
		t.Fatalf("CreateCertificate with template %q: %v", template, err)
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

	t.Logf("issued with %q: serial=%s id=%s valid %s..%s", template,
		cert.SerialNumber, cert.ID,
		cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))

	if _, err := cert.ParsePEM(); err != nil {
		t.Errorf("ParsePEM: %v", err)
	}

	// The leaf is always part of the full chain; the remaining material is
	// optional and depends on how the CA is installed.
	if len(cert.FullChain) == 0 {
		t.Error("expected FullChain in the issue response")
	} else if !bytes.HasPrefix(cert.FullChain, cert.PEM) {
		t.Error("FullChain does not start with the leaf certificate")
	}

	if len(cert.Root) > 0 {
		block, _ := pem.Decode(cert.Root)
		if block == nil {
			t.Error("Root is not PEM-encoded")
		} else if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Errorf("Root does not parse: %v", err)
		}
	}

	t.Logf("chain: chain=%dB fullchain=%dB root=%dB pkcs7=%dB dnHash=%q",
		len(cert.Chain), len(cert.FullChain), len(cert.Root), len(cert.PKCS7), cert.DNHash)

	// A certificate must be recoverable from its serial alone.
	recovered, err := client.GetCertificate(t.Context(), cert.SerialNumber)
	if err != nil {
		t.Fatalf("GetCertificate(%s): %v", cert.SerialNumber, err)
	}

	if !bytes.Equal(recovered.PEM, cert.PEM) {
		t.Error("GetCertificate returned a different certificate")
	}

	if recovered.ID != cert.ID {
		t.Errorf("recovered request id = %v, want %v", recovered.ID, cert.ID)
	}

	t.Logf("recovered by serial: status=%s bytes=%d", recovered.Status, len(recovered.PEM))

	if err := client.RevokeCertificate(t.Context(), cert.ID); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}

	secondErr := client.RevokeCertificate(t.Context(), cert.ID)
	if secondErr == nil {
		t.Fatal("expected the second revocation to fail")
	}

	// A reconciliation loop can treat "already revoked" as success.
	if err := client.RevokeCertificateWithOptions(
		t.Context(), cert.ID, safetech.RevokeOptions{AllowAlreadyRevoked: true},
	); err != nil {
		t.Fatalf("idempotent revoke: %v (second revoke reported %v)", err, secondErr)
	}

	t.Log("idempotent revoke: ok")
}
