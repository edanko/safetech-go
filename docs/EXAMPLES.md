# Examples

Recipes for common tasks. Snippets are partial: they assume surrounding function
scope (`ctx`, `err`, `cert`, `cfg`) and imports (`context`, `errors`, `log`,
`os`, `time`). Placeholders: `https://ca.example.com:7443`,
`https://keycloak.example.com/realms/ca`, `MY_TEMPLATE`.

## Issue a certificate from a CSR file

```go
csrPEM, err := os.ReadFile("device.csr")
if err != nil {
	return err
}
client, err := safetech.New(safetech.Config{
	BaseURL:  "https://ca.example.com:7443",
	Username: os.Getenv("STCA_USERNAME"),
	Password: os.Getenv("STCA_PASSWORD"),
})
if err != nil {
	return err
}
cert, err := client.CreateCertificate(ctx, csrPEM, "MY_TEMPLATE")
if err != nil {
	return err
}
log.Printf("serial=%s valid %s..%s", cert.SerialNumber, cert.NotBefore, cert.NotAfter)
```

## Discover templates and issue with one

```go
templates, err := client.ListTemplates(ctx)
if err != nil {
	return err
}

var templateName string

for _, tmpl := range templates {
	stca := tmpl.Context.STCAEnrollment
	if tmpl.Deleted || tmpl.ProtocolType != safetech.TemplateProtocolSTCA || stca == nil {
		continue
	}

	if stca.EnrollmentScenario == "STANDARD" {
		templateName = tmpl.Name

		break
	}
}

if templateName == "" {
	return errors.New("no usable ST_CA template")
}

cert, err := client.CreateCertificate(ctx, csrPEM, templateName)
if err != nil {
	return err
}
```

## Revoke a certificate with an explicit reason

```go
// The client is constructed with RevokeReason: safetech.RevokeReasonKeyCompromise.
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
if err := client.RevokeCertificate(ctx, cert.ID); err != nil {
	if errors.Is(err, safetech.ErrCertificateRevoked) {
		log.Printf("already revoked")
	} else {
		return err
	}
}
```

## Keep your own interface for dependency injection

The library ships a concrete `*Client` and no interface. Declare the narrow
interface your application needs where you consume it; `*Client` satisfies it,
and tests can substitute a fake.

```go
type CertificateIssuer interface {
	CreateCertificate(ctx context.Context, csrPEM []byte, templateName string) (*safetech.UserCertificate, error)
}

type Enroller struct{ ca CertificateIssuer }

func NewEnroller(ca CertificateIssuer) *Enroller { return &Enroller{ca: ca} }

func (e *Enroller) Enroll(ctx context.Context, csrPEM []byte) (*safetech.UserCertificate, error) {
	return e.ca.CreateCertificate(ctx, csrPEM, "MY_TEMPLATE")
}
```
