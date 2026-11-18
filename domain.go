package safetech

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
	"uuid"
)

// IssuedCertificate is a certificate issued by the CA.
//
// It carries the identifiers needed both to inspect the certificate and to
// revoke it later.
type IssuedCertificate struct {
	// ID identifies the issuance request. It is the value to pass to
	// [Client.RevokeCertificate]; the CA resolves the certificate serial
	// number from it.
	ID uuid.UUID
	// SerialNumber is the serial number assigned by the CA, in the
	// encoding used by the ca-core API.
	SerialNumber string
	// PEM is the issued leaf certificate in PEM encoding.
	PEM []byte
	// Chain is the issuing chain in PEM encoding, without the leaf. It is
	// nil when the CA issued the certificate directly from the root.
	Chain []byte
	// FullChain is the leaf certificate followed by its chain, in PEM
	// encoding. It is what a TLS server hands to clients.
	FullChain []byte
	// Root is the root CA certificate in PEM encoding, suitable for adding
	// to a trust store.
	Root []byte
	// PKCS7 is the certificate together with its chain as a PEM-encoded
	// PKCS#7 (CMS SignedData) bundle.
	PKCS7 []byte
	// DNHash is the CA-side hash of the certificate distinguished name, in
	// hexadecimal. The CA uses it to group certificates per subject.
	DNHash string
	// TemplateName is the CA template the certificate was issued from.
	TemplateName string
	// Status is the certificate status reported by the CA, for example
	// "ACTIVE".
	Status string
	// NotBefore is the start of the validity period. The CA reports
	// timestamps without a time zone, so it is interpreted as UTC.
	NotBefore time.Time
	// NotAfter is the end of the validity period. The CA reports
	// timestamps without a time zone, so it is interpreted as UTC.
	NotAfter time.Time
}

// TemplateProtocol is the enrollment protocol a certificate template serves.
type TemplateProtocol string

// Enrollment protocols reported by the CA.
const (
	// TemplateProtocolSTCA is the CA API enrollment protocol this client
	// issues certificates with.
	TemplateProtocolSTCA TemplateProtocol = "ST_CA"
	// TemplateProtocolSCEP is SCEP enrollment.
	TemplateProtocolSCEP TemplateProtocol = "SCEP"
	// TemplateProtocolACME is ACME enrollment.
	TemplateProtocolACME TemplateProtocol = "ACME"
	// TemplateProtocolMSEnrollment is Microsoft autoenrollment.
	TemplateProtocolMSEnrollment TemplateProtocol = "MS_ENROLLMENT"
)

// CertificateTemplate is a certificate template configured in the CA.
type CertificateTemplate struct {
	// ID is the server-side identifier of the template.
	ID string
	// Name is the template name to pass to [Client.CreateCertificate].
	Name string
	// Description is the free-form template description.
	Description string
	// OID is the object identifier assigned to the template.
	OID string
	// ProtocolType is the enrollment protocol the template serves.
	ProtocolType TemplateProtocol
	// MaxValidityPeriod is the maximum certificate lifetime in days.
	MaxValidityPeriod int
	// MinKeySize is the minimum accepted key size in bits.
	MinKeySize int
	// KeyUsages is the X.509 key-usage bitmask configured on the template.
	KeyUsages int
	// Deleted reports whether the CA marks the template as deleted.
	Deleted bool
	// Context holds the enrollment settings the client can interpret.
	Context TemplateContext
}

// TemplateContext is the enrollment configuration of a certificate template.
type TemplateContext struct {
	// STCAEnrollment is set for templates that use the ST_CA protocol.
	STCAEnrollment *STCAEnrollmentContext
	// Common is set when the template carries protocol-independent settings.
	Common *CommonContext
}

// STCAEnrollmentContext is the ST_CA-specific part of a template.
type STCAEnrollmentContext struct {
	// EnrollmentScenario is the issuance scenario, for example STANDARD,
	// TOKEN_BASED or API_ONLY.
	EnrollmentScenario string
	// CryptoTypes lists the accepted key algorithms, for example RSA or
	// ECDSA.
	CryptoTypes []string
	// KeySizes lists the accepted key sizes in bits.
	KeySizes []int
	// SignatureAlgorithms lists the accepted signature algorithms.
	SignatureAlgorithms []string
	// RequiredSubjectAlternativeNames lists the subject alternative names a
	// request must carry.
	RequiredSubjectAlternativeNames []string
	// IncludeSID reports whether the CA embeds the account SID in the
	// certificate.
	IncludeSID bool
	// SupportedToken names the hardware token the template targets, if any.
	SupportedToken string
	// InstallRutokenConfig reports whether the Rutoken configuration is
	// installed with the certificate.
	InstallRutokenConfig bool
}

// CommonContext is the protocol-independent part of a template.
type CommonContext struct {
	// CheckUniquePublicKeys reports whether the CA rejects a public key that
	// is already registered.
	CheckUniquePublicKeys bool
	// ApplyKeyUsages reports whether the key usages of the template are
	// applied to the certificate.
	ApplyKeyUsages bool
	// ApplyExtendedKeyUsages reports whether the extended key usages of the
	// template are applied to the certificate.
	ApplyExtendedKeyUsages bool
}

// ParsePEM parses the issued leaf certificate.
func (c *IssuedCertificate) ParsePEM() (*x509.Certificate, error) {
	if len(c.PEM) == 0 {
		return nil, errors.New("safetech: certificate PEM is empty")
	}

	block, _ := pem.Decode(c.PEM)
	if block == nil {
		return nil, errors.New("safetech: certificate PEM contains no PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("safetech: parse certificate: %w", err)
	}

	return cert, nil
}
