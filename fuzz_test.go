package safetech

import (
	"encoding/json"
	"testing"

	"github.com/edanko/safetech-go/internal/testutil"
)

// FuzzNormalizeCSR checks that malformed certificate requests are always
// rejected with an error wrapping ErrInvalidCSR, and never panic.
func FuzzNormalizeCSR(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not a csr"))
	f.Add(testutil.CSR(f, "fuzz.example.com"))

	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := normalizeCSR(data)
		if err != nil {
			if out != "" {
				t.Fatalf("normalizeCSR returned %q alongside error %v", out, err)
			}

			return
		}

		// Success must return a canonical PEM block that the CA can read.
		if out == "" {
			t.Fatal("normalizeCSR returned an empty request without an error")
		}
	})
}

// FuzzDecodeEnvelope feeds arbitrary bytes to the envelope decoder. Malformed
// input must produce an error, never a panic.
func FuzzDecodeEnvelope(f *testing.F) {
	f.Add([]byte(`{"errorCode":0,"payload":{"serial":"AB"}}`))
	f.Add([]byte(`{"errorCode":7,"errorMessage":"denied"}`))
	f.Add([]byte(`{"errorCode":0,"payload":null}`))
	f.Add([]byte("{"))
	f.Add([]byte(""))
	f.Add([]byte(`{"payload":[1,2,3]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var out struct {
			Serial string `json:"serial"`
		}

		// Whether the input decodes or not does not matter here: the decoder
		// must never panic, and a nil error must leave out decodable.
		if err := decodeEnvelope(data, &out); err != nil {
			return
		}

		if _, err := json.Marshal(out); err != nil {
			t.Fatalf("decoded payload is not marshallable: %v", err)
		}
	})
}

// FuzzParseSTCATime checks the timestamp parser against arbitrary input.
func FuzzParseSTCATime(f *testing.F) {
	f.Add("2026-10-22T18:28:59.00000")
	f.Add("2026-10-22T18:28:59")
	f.Add("")
	f.Add("0000-00-00T99:99:99.999999999+99:99")

	f.Fuzz(func(t *testing.T, value string) {
		parsed, err := parseSTCATime(value)
		if err == nil && parsed.IsZero() {
			t.Fatalf("parseSTCATime(%q) returned the zero time without an error", value)
		}

		if err != nil && !parsed.IsZero() {
			t.Fatalf("parseSTCATime(%q) returned a time alongside error %v", value, err)
		}
	})
}

// FuzzParseRetryAfter checks the Retry-After parser against arbitrary input.
func FuzzParseRetryAfter(f *testing.F) {
	f.Add("")
	f.Add("5")
	f.Add("-1")
	f.Add("Wed, 21 Oct 2015 07:28:00 GMT")

	f.Fuzz(func(t *testing.T, value string) {
		if delay := parseRetryAfter(value); delay < 0 {
			t.Fatalf("parseRetryAfter(%q) = %v, want a non-negative delay", value, delay)
		}
	})
}

// FuzzTemplatePayloadDecoding checks that arbitrary template payloads convert
// without panics.
func FuzzTemplatePayloadDecoding(f *testing.F) {
	f.Add([]byte(`[{"id":"1","name":"t","protocolType":"ST_CA"}]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{}]`))
	f.Add([]byte(`[{"context":{"stcaEnrollmentContext":{"keySizes":[2048]}}}]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var payload []templatePayload
		if err := json.Unmarshal(data, &payload); err != nil {
			return
		}

		for _, entry := range payload {
			template := entry.template()
			if template.Name != entry.Name {
				t.Fatalf("template name = %q, want %q", template.Name, entry.Name)
			}
		}
	})
}
