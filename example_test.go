package safetech_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"
	"uuid"

	"github.com/edanko/safetech"
)

// newClient is the shared setup used by the examples.
func newClient() (*safetech.Client, error) {
	return safetech.New(safetech.Config{
		BaseURL:  "https://ca.example.com:7443",
		Username: os.Getenv("STCA_USERNAME"),
		Password: os.Getenv("STCA_PASSWORD"),
	})
}

// Example shows how to construct a client. The examples have no output
// assertions: they exist so the documented API is compiled by `go test`.
func Example() {
	client, err := newClient()
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	// The client holds no resources that need closing and is safe for
	// concurrent use.
	_ = client
}

// ExampleClient_CreateCertificate issues a certificate from a CSR.
func ExampleClient_CreateCertificate() {
	client, err := newClient()
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	csrPEM, err := os.ReadFile("device.csr")
	if err != nil {
		log.Fatalf("read CSR: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cert, err := client.CreateCertificate(ctx, csrPEM, "MY_TEMPLATE")
	if err != nil {
		log.Printf("issue certificate: %v", err)

		return
	}

	fmt.Printf("serial: %s, status: %s\n", cert.SerialNumber, cert.Status)

	// ID is what revokes the certificate later.
	fmt.Printf("request id: %s\n", cert.ID)
}

// ExampleClient_ListTemplates discovers the templates and their constraints.
func ExampleClient_ListTemplates() {
	client, err := newClient()
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	templates, err := client.ListTemplates(context.Background())
	if err != nil {
		log.Fatalf("list templates: %v", err)
	}

	for _, tmpl := range templates {
		// Only ST_CA templates with the STANDARD scenario can be used for API
		// issuance.
		if tmpl.Deleted || tmpl.ProtocolType != safetech.TemplateProtocolSTCA {
			continue
		}

		if tmpl.Context.STCAEnrollment == nil ||
			tmpl.Context.STCAEnrollment.EnrollmentScenario != "STANDARD" {
			continue
		}

		fmt.Println(tmpl.Name, tmpl.MaxValidityPeriod, tmpl.MinKeySize)
	}
}

// ExampleClient_RevokeCertificateWithOptions revokes idempotently, which is what
// reconciliation loops want.
func ExampleClient_RevokeCertificateWithOptions() {
	client, err := newClient()
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	// cert normally comes from CreateCertificate; the ID is what matters here.
	cert := &safetech.UserCertificate{ID: uuid.MustParse("6f9d7e3a-1c2b-4d5e-8f90-112233445566")}

	ctx := context.Background()

	err = client.RevokeCertificateWithOptions(ctx, cert.ID, safetech.RevokeOptions{
		AllowAlreadyRevoked: true,
	})
	if err != nil && !errors.Is(err, safetech.ErrCertificateNotFound) {
		log.Fatalf("revoke certificate: %v", err)
	}
}

// ExampleConfig_directCACore addresses ca-core without the gateway.
func ExampleConfig_directCACore() {
	client, err := safetech.New(safetech.Config{
		// The gateway is bypassed, so the full ca-core API base URL is used and
		// AuthURL is required: /api/ui-config is only served by the gateway.
		APIBaseURL: "http://ca-core.example.com:8081/api/v1",
		AuthURL:    "https://keycloak.example.com/realms/ca",
		Username:   os.Getenv("STCA_USERNAME"),
		Password:   os.Getenv("STCA_PASSWORD"),
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	_ = client
}

// ExampleRetryPolicy shows the retry configuration.
func ExampleRetryPolicy() {
	client, err := safetech.New(safetech.Config{
		BaseURL:  "https://ca.example.com:7443",
		Username: os.Getenv("STCA_USERNAME"),
		Password: os.Getenv("STCA_PASSWORD"),
		Retry: safetech.RetryPolicy{
			MaxAttempts: 5,
			Backoff:     500 * time.Millisecond,
			MaxBackoff:  10 * time.Second,
		},
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	_ = client
}
