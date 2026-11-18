# Examples

Recipes for common tasks. Snippets are partial: they assume surrounding function
scope (`err`, `cert`, `cfg`) and imports (`context`, `errors`, `log`, `os`,
`time`, `uuid`). `Adapter` methods use `context.Background()`; hold a `*Client`
when you need timeouts or cancellation. Placeholders: `https://ca.example.com:7443`,
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
cert, err := client.CreateCertificate(csrPEM, "MY_TEMPLATE")
if err != nil {
	return err
}
log.Printf("serial=%s valid %s..%s", cert.SerialNumber, cert.NotBefore, cert.NotAfter)
```

## Revoke a certificate with an explicit reason

```go
// The client is constructed with RevokeReason: safetech.RevokeReasonKeyCompromise.
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
if err := client.RevokeCertificateContext(ctx, cert.ID); err != nil {
	if errors.Is(err, safetech.ErrCertificateRevoked) {
		log.Printf("already revoked")
	} else {
		return err
	}
}
```

## Wire the Adapter interface into an application

```go
type Enroller struct{ ca safetech.Adapter }

func NewEnroller(ca safetech.Adapter) *Enroller { return &Enroller{ca: ca} }

func (e *Enroller) Enroll(csrPEM []byte) (*safetech.UserCertificate, error) {
	return e.ca.CreateCertificate(csrPEM, "MY_TEMPLATE")
}

client, err := safetech.New(cfg) // *Client implements safetech.Adapter
if err != nil {
	return err
}
enroller := NewEnroller(client)

type fakeCA struct{} // test double with the same two methods

func (fakeCA) CreateCertificate([]byte, string) (*safetech.UserCertificate, error) {
	return &safetech.UserCertificate{}, nil
}

func (fakeCA) RevokeCertificate(uuid.UUID) error { return nil }
```
