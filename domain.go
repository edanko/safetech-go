package safetech

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
	"uuid"
)

// UserCertificate is a certificate issued by the CA on behalf of a request.
type UserCertificate struct {
	// ID identifies the issuance request. It is the value to pass to
	// [Client.RevokeCertificate]; the CA resolves the certificate serial
	// number from it.
	ID uuid.UUID
	// SerialNumber is the serial number assigned by the CA, in the
	// encoding used by the ca-core API.
	SerialNumber string
	// PEM is the issued certificate in PEM encoding, as returned by the
	// CA.
	PEM []byte
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

// ParsePEM parses the issued leaf certificate.
func (c *UserCertificate) ParsePEM() (*x509.Certificate, error) {
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
