// Package testutil provides certificate fixtures shared by the safetech tests.
// It is internal to the module and never imported by the library itself.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// keyUsageOID is the OID of the X.509 keyUsage extension.
var keyUsageOID = asn1.ObjectIdentifier{2, 5, 29, 15}

// keyUsageDER encodes digitalSignature and keyEncipherment, which the SafeTech CA
// templates require. ASN.1 BIT STRING bits are numbered from the most
// significant bit: digitalSignature is bit 0, keyEncipherment is bit 2.
func keyUsageDER(tb testing.TB) []byte {
	tb.Helper()

	der, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0b1010_0000}, BitLength: 3})
	if err != nil {
		tb.Fatalf("marshal key usage: %v", err)
	}

	return der
}

// CSR returns a PEM-encoded PKCS#10 certificate signing request for the given
// common name, signed with a throwaway ECDSA P-256 key.
func CSR(tb testing.TB, commonName string) []byte {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: []string{commonName},
		ExtraExtensions: []pkix.Extension{{
			Id:       keyUsageOID,
			Critical: true,
			Value:    keyUsageDER(tb),
		}},
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		tb.Fatalf("create certificate request: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// Certificate returns a PEM-encoded self-signed certificate for the given common
// name.
func Certificate(tb testing.TB, commonName string) []byte {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		tb.Fatalf("generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              []string{commonName},
		NotBefore:             time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
