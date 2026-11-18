package safetech

import (
	"bytes"
	"encoding/pem"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/edanko/safetech-go/internal/testutil"
)

func TestDecodeEnvelope(t *testing.T) {
	t.Parallel()

	type payload struct {
		Serial string `json:"serial"`
	}

	tests := map[string]struct {
		raw     string
		out     *payload
		want    string
		wantErr string
	}{
		"payload decoded": {
			raw:  `{"errorCode":0,"errorMessage":"","payload":{"serial":"AB"}}`,
			out:  &payload{},
			want: "AB",
		},
		"null payload": {
			raw: `{"errorCode":0,"payload":null}`,
			out: &payload{},
		},
		"empty body": {
			raw: "",
			out: &payload{},
		},
		"no payload field": {
			raw: `{"errorCode":0}`,
			out: &payload{},
		},
		"nil out": {
			raw: `{"errorCode":0,"payload":{"serial":"AB"}}`,
		},
		"invalid json": {
			raw:     "{",
			out:     &payload{},
			wantErr: "decode response envelope",
		},
		"invalid payload": {
			raw:     `{"errorCode":0,"payload":"not-an-object"}`,
			out:     &payload{},
			wantErr: "decode response payload",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var out any
			if test.out != nil {
				out = test.out
			}

			err := decodeEnvelope([]byte(test.raw), out)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("decodeEnvelope error = %v, want it to contain %q", err, test.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("decodeEnvelope: %v", err)
			}

			if test.out != nil && test.want != "" && test.out.Serial != test.want {
				t.Errorf("serial = %q, want %q", test.out.Serial, test.want)
			}
		})
	}
}

func TestDecodeEnvelopeReportsAPIError(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		raw  string
		code int
		msg  string
	}{
		"code and message": {
			raw:  `{"errorCode":7,"errorMessage":"denied"}`,
			code: 7,
			msg:  "denied",
		},
		"message only": {
			raw: `{"errorCode":0,"errorMessage":"  denied  "}`,
			msg: "denied",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := decodeEnvelope([]byte(test.raw), nil)
			if err == nil {
				t.Fatal("expected an error")
			}

			apiErr, ok := errors.AsType[*APIError](err)
			if !ok {
				t.Fatalf("error = %v, want an *APIError", err)
			}

			if apiErr.Code != test.code {
				t.Errorf("Code = %d, want %d", apiErr.Code, test.code)
			}

			if apiErr.Message != test.msg {
				t.Errorf("Message = %q, want %q", apiErr.Message, test.msg)
			}
		})
	}
}

func TestNewHTTPError(t *testing.T) {
	t.Parallel()

	t.Run("truncates long bodies", func(t *testing.T) {
		t.Parallel()

		httpErr := newHTTPError(500, http.Header{}, []byte(strings.Repeat("x", maxErrorBodyBytes*2)))
		if got := len(httpErr.Body); got > maxErrorBodyBytes+len("…") {
			t.Errorf("Body length = %d, want at most %d", got, maxErrorBodyBytes+len("…"))
		}
	})

	t.Run("keeps short bodies", func(t *testing.T) {
		t.Parallel()

		httpErr := newHTTPError(502, http.Header{}, []byte("  gateway unavailable\n"))
		if httpErr.Body != "gateway unavailable" {
			t.Errorf("Body = %q, want %q", httpErr.Body, "gateway unavailable")
		}

		if httpErr.StatusCode != http.StatusBadGateway {
			t.Errorf("StatusCode = %d, want %d", httpErr.StatusCode, http.StatusBadGateway)
		}
	})

	t.Run("renders without body", func(t *testing.T) {
		t.Parallel()

		httpErr := newHTTPError(503, http.Header{}, nil)
		if got, want := httpErr.Error(), "safetech: http 503"; got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})
}

func TestTruncateKeepsValidUTF8(t *testing.T) {
	t.Parallel()

	// "é" is two bytes, so a byte-boundary cut would split a rune.
	s := strings.Repeat("é", 10)

	got := truncate(s, 5)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncate(%q, 5) = %q, want it to end with an ellipsis", s, got)
	}

	if len(got) > 5+len("…") {
		t.Errorf("truncate(%q, 5) = %q, want at most 5 bytes plus the ellipsis", s, got)
	}

	if !utf8Valid(got) {
		t.Errorf("truncate(%q, 5) = %q, want valid UTF-8", s, got)
	}
}

// utf8Valid reports whether s is valid UTF-8, without importing unicode/utf8 in
// the test for a single call site.
func utf8Valid(s string) bool {
	return strings.ToValidUTF8(s, "") == s
}

func TestParseSTCATime(t *testing.T) {
	t.Parallel()

	want := time.Date(2026, time.October, 22, 18, 28, 59, 0, time.UTC)

	tests := map[string]struct {
		in      string
		want    time.Time
		wantErr bool
	}{
		"five digit fraction": {
			in:   "2026-10-22T18:28:59.00000",
			want: want,
		},
		"no fraction": {
			in:   "2026-10-22T18:28:59",
			want: want,
		},
		"nanoseconds": {
			in:   "2026-10-22T18:28:59.000000000",
			want: want,
		},
		"surrounding whitespace": {
			in:   "  2026-10-22T18:28:59  ",
			want: want,
		},
		"empty": {
			in:      "",
			wantErr: true,
		},
		"unsupported layout": {
			in:      "22.10.2026 18:28:59",
			wantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := parseSTCATime(test.in)
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "unsupported time format") {
					t.Fatalf("parseSTCATime(%q) error = %v, want an unsupported-format error", test.in, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("parseSTCATime(%q): %v", test.in, err)
			}

			if !got.Equal(test.want) {
				t.Errorf("parseSTCATime(%q) = %v, want %v", test.in, got, test.want)
			}

			if got.Location() != time.UTC {
				t.Errorf("location = %v, want UTC", got.Location())
			}
		})
	}
}

func TestNormalizeCSR(t *testing.T) {
	t.Parallel()

	validCSR := testutil.CSR(t, "device.example.com")

	t.Run("canonicalises a valid request", func(t *testing.T) {
		t.Parallel()

		// Leading and trailing whitespace must be trimmed.
		got, err := normalizeCSR([]byte("\n\n" + string(validCSR) + "\n\n"))
		if err != nil {
			t.Fatalf("normalizeCSR: %v", err)
		}

		block, rest := pem.Decode([]byte(got))
		if block == nil {
			t.Fatal("output is not PEM-encoded")
		}

		if len(bytes.TrimSpace(rest)) != 0 {
			t.Errorf("output has data after the first PEM block: %q", rest)
		}

		if !strings.HasSuffix(got, "\n") {
			t.Error("output does not end with a newline")
		}

		original, _ := pem.Decode(validCSR)
		if !bytes.Equal(block.Bytes, original.Bytes) {
			t.Error("output does not preserve the request bytes")
		}
	})

	t.Run("rejects invalid requests", func(t *testing.T) {
		t.Parallel()

		block, _ := pem.Decode(validCSR)
		if block == nil {
			t.Fatal("test fixture is not PEM-encoded")
		}

		tampered := *block

		tampered.Bytes = slices.Clone(block.Bytes)
		tampered.Bytes[len(tampered.Bytes)-1] ^= 0xFF

		certificateBlock, _ := pem.Decode(testutil.Certificate(t, "device.example.com"))

		tests := map[string][]byte{
			"empty":              nil,
			"whitespace":         []byte(" \t\n"),
			"not pem":            []byte("hello"),
			"wrong block type":   pem.EncodeToMemory(certificateBlock),
			"invalid der":        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("nope")}),
			"tampered signature": pem.EncodeToMemory(&tampered),
		}

		for name, input := range tests {
			got, err := normalizeCSR(input)
			if !errors.Is(err, ErrInvalidCSR) {
				t.Errorf("%s: error = %v, want it to wrap ErrInvalidCSR", name, err)
			}

			if got != "" {
				t.Errorf("%s: output = %q, want an empty string", name, got)
			}
		}
	})
}

func TestActiveSerialAndHasStatus(t *testing.T) {
	t.Parallel()

	certs := []certPayload{
		{Status: "PENDING", SerialNumber: "01"},
		{Status: statusActive, SerialNumber: ""},
		{Status: statusActive, SerialNumber: testSerial},
		{Status: statusRevoked, SerialNumber: "02"},
	}

	serial, ok := activeSerial(certs)
	if !ok || serial != testSerial {
		t.Errorf("activeSerial() = %q, %t; want %q, true", serial, ok, testSerial)
	}

	if _, ok := activeSerial(nil); ok {
		t.Error("activeSerial(nil) = true, want false")
	}

	if !hasStatus(certs, statusRevoked) {
		t.Error("hasStatus(statusRevoked) = false, want true")
	}

	if hasStatus(certs, "UNKNOWN") {
		t.Error("hasStatus(UNKNOWN) = true, want false")
	}
}

func TestCertFromIssue(t *testing.T) {
	t.Parallel()

	fixture := func() issuePayload {
		return issuePayload{
			CertificateInfo: certPayload{
				Status:       statusActive,
				SerialNumber: testSerial,
				PEM:          string(testutil.Certificate(t, "issued.example.com")),
				NotBefore:    "2026-10-22T18:28:59.00000",
				NotAfter:     "2027-10-22T18:28:59.00000",
			},
			CertificateRequest: reqPayload{ID: testRequestID},
		}
	}

	t.Run("maps every field", func(t *testing.T) {
		t.Parallel()

		cert, err := certFromIssue(fixture(), testTemplate)
		if err != nil {
			t.Fatalf("certFromIssue: %v", err)
		}

		if cert.ID.String() != testRequestID {
			t.Errorf("ID = %v, want %s", cert.ID, testRequestID)
		}

		if cert.SerialNumber != testSerial {
			t.Errorf("SerialNumber = %q, want %q", cert.SerialNumber, testSerial)
		}

		if cert.Status != statusActive {
			t.Errorf("Status = %q, want %q", cert.Status, statusActive)
		}

		if cert.TemplateName != testTemplate {
			t.Errorf("TemplateName = %q, want %q", cert.TemplateName, testTemplate)
		}

		if _, err := cert.ParsePEM(); err != nil {
			t.Errorf("ParsePEM: %v", err)
		}
	})

	t.Run("accepts empty validity dates", func(t *testing.T) {
		t.Parallel()

		payload := fixture()
		payload.CertificateInfo.NotBefore = ""
		payload.CertificateInfo.NotAfter = ""

		cert, err := certFromIssue(payload, testTemplate)
		if err != nil {
			t.Fatalf("certFromIssue: %v", err)
		}

		if !cert.NotBefore.IsZero() || !cert.NotAfter.IsZero() {
			t.Errorf("validity = %v..%v, want zero values", cert.NotBefore, cert.NotAfter)
		}
	})

	t.Run("rejects malformed responses", func(t *testing.T) {
		t.Parallel()

		tests := map[string]struct {
			mutate  func(*issuePayload)
			wantErr string
		}{
			"bad request id": {
				mutate:  func(p *issuePayload) { p.CertificateRequest.ID = "not-a-uuid" },
				wantErr: "parse request id",
			},
			"missing certificate": {
				mutate:  func(p *issuePayload) { p.CertificateInfo.PEM = "  " },
				wantErr: "contains no certificate",
			},
			"bad not before": {
				mutate:  func(p *issuePayload) { p.CertificateInfo.NotBefore = "yesterday" },
				wantErr: "unsupported time format",
			},
			"bad not after": {
				mutate:  func(p *issuePayload) { p.CertificateInfo.NotAfter = "tomorrow" },
				wantErr: "unsupported time format",
			},
		}

		for name, test := range tests {
			payload := fixture()
			test.mutate(&payload)

			_, err := certFromIssue(payload, testTemplate)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("%s: error = %v, want it to contain %q", name, err, test.wantErr)
			}
		}
	})
}
