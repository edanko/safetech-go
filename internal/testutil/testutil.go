// Package testutil provides certificate fixtures shared by the safetech tests.
// It is internal to the module and never imported by the library itself.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
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

// CA is a throwaway certificate authority for TLS tests.
type CA struct {
	// RootPEM is the PEM-encoded CA certificate, suitable for a client trust
	// store.
	RootPEM []byte
	// ServerCertificate is a server certificate signed by the CA, valid for
	// 127.0.0.1 and localhost so an httptest server can use it.
	ServerCertificate tls.Certificate
}

// NewCA returns a CA that exists only for the duration of the test.
func NewCA(tb testing.TB) *CA {
	tb.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          serialNumber(tb),
		Subject:               pkix.Name{CommonName: "test root CA"},
		NotBefore:             time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		tb.Fatalf("create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		tb.Fatalf("parse CA certificate: %v", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generate server key: %v", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serialNumber(tb),
		Subject:      pkix.Name{CommonName: "test server"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2036, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		tb.Fatalf("create server certificate: %v", err)
	}

	return &CA{
		RootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		ServerCertificate: tls.Certificate{
			Certificate: [][]byte{serverDER},
			PrivateKey:  serverKey,
		},
	}
}

// serialNumber returns a random positive serial number for a test certificate.
func serialNumber(tb testing.TB) *big.Int {
	tb.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		tb.Fatalf("generate serial: %v", err)
	}

	return serial
}
