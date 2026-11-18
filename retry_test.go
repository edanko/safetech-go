package safetech

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()

	future := time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)

	tests := map[string]struct {
		value string
		want  time.Duration
		exact bool
	}{
		"empty":       {value: "", want: 0},
		"seconds":     {value: "5", want: 5 * time.Second, exact: true},
		"zero":        {value: "0", want: 0},
		"negative":    {value: "-3", want: 0},
		"garbage":     {value: "soon", want: 0},
		"overflow":    {value: "10000000000", want: maxRetryAfter, exact: true},
		"past date":   {value: past, want: 0},
		"future date": {value: future, want: time.Second, exact: false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := parseRetryAfter(test.value)
			if test.exact && got != test.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", test.value, got, test.want)
			}

			if !test.exact && got < test.want {
				t.Errorf("parseRetryAfter(%q) = %v, want at least %v", test.value, got, test.want)
			}
		})
	}
}

func TestNewRetryPolicy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		policy      RetryPolicy
		wantAttempt int
	}{
		"zero value uses defaults": {policy: RetryPolicy{}, wantAttempt: defaultRetryAttempts},
		"explicit attempts":        {policy: RetryPolicy{MaxAttempts: 5}, wantAttempt: 5},
		"single attempt":           {policy: RetryPolicy{MaxAttempts: 1}, wantAttempt: 1},
		"negative attempts":        {policy: RetryPolicy{MaxAttempts: -2}, wantAttempt: 1},
		"disabled":                 {policy: RetryPolicy{Disabled: true, MaxAttempts: 9}, wantAttempt: 1},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := newRetryPolicy(test.policy)
			if got.maxAttempts != test.wantAttempt {
				t.Errorf("maxAttempts = %d, want %d", got.maxAttempts, test.wantAttempt)
			}

			if got.backoff <= 0 || got.maxBackoff <= 0 {
				t.Errorf("backoff = %v, maxBackoff = %v; want positive values", got.backoff, got.maxBackoff)
			}
		})
	}
}

func TestRetryDelay(t *testing.T) {
	t.Parallel()

	client := &Client{retry: retryPolicy{
		maxAttempts: 5,
		backoff:     100 * time.Millisecond,
		maxBackoff:  time.Second,
	}}

	tests := map[string]struct {
		attempt int
		err     error
		want    time.Duration
	}{
		"first retry":  {attempt: 1, want: 100 * time.Millisecond},
		"second retry": {attempt: 2, want: 200 * time.Millisecond},
		"capped":       {attempt: 6, want: time.Second},
		"server hint": {
			attempt: 1,
			err:     &HTTPError{StatusCode: http.StatusTooManyRequests, RetryAfter: 250 * time.Millisecond},
			want:    250 * time.Millisecond,
		},
		"hint capped by max backoff": {
			attempt: 1,
			err:     &HTTPError{StatusCode: 503, RetryAfter: time.Hour},
			want:    time.Second,
		},
		"hint shorter than backoff": {
			attempt: 4,
			err:     &HTTPError{StatusCode: 503, RetryAfter: 10 * time.Millisecond},
			want:    10 * time.Millisecond,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := client.retryDelay(test.attempt, test.err); got != test.want {
				t.Errorf("retryDelay(%d) = %v, want %v", test.attempt, got, test.want)
			}
		})
	}
}

func TestIsRetryable(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		want bool
	}{
		"nil":                   {err: nil, want: false},
		"api error":             {err: &APIError{Code: 1}, want: false},
		"bad request":           {err: &HTTPError{StatusCode: http.StatusBadRequest}, want: false},
		"not found":             {err: &HTTPError{StatusCode: http.StatusNotFound}, want: false},
		"too many requests":     {err: &HTTPError{StatusCode: http.StatusTooManyRequests}, want: true},
		"internal server error": {err: &HTTPError{StatusCode: http.StatusInternalServerError}, want: true},
		"bad gateway":           {err: &HTTPError{StatusCode: http.StatusBadGateway}, want: true},
		"context canceled":      {err: context.Canceled, want: false},
		"deadline exceeded":     {err: context.DeadlineExceeded, want: false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := isRetryable(test.err); got != test.want {
				t.Errorf("isRetryable(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestRetryableRetriesTransientFailures(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32

	client := &Client{retry: retryPolicy{
		maxAttempts: 3,
		backoff:     time.Millisecond,
		maxBackoff:  5 * time.Millisecond,
	}}

	err := client.retryable(t.Context(), "test", func() error {
		if attempts.Add(1) < 3 {
			return &HTTPError{StatusCode: http.StatusInternalServerError}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("retryable: %v", err)
	}

	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestRetryableStopsOnPermanentFailure(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32

	client := &Client{retry: retryPolicy{maxAttempts: 5, backoff: time.Millisecond, maxBackoff: time.Millisecond}}

	err := client.retryable(t.Context(), "test", func() error {
		attempts.Add(1)

		return &HTTPError{StatusCode: http.StatusBadRequest}
	})
	if err == nil {
		t.Fatal("expected an error")
	}

	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}

	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusBadRequest {
		t.Errorf("error = %v, want the *HTTPError to be returned unchanged", err)
	}
}

func TestRetryableDoesNotRetryWhenContextIsDone(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var attempts atomic.Int32

	client := &Client{retry: retryPolicy{maxAttempts: 5, backoff: time.Hour, maxBackoff: time.Hour}}

	err := client.retryable(ctx, "test", func() error {
		attempts.Add(1)

		return &HTTPError{StatusCode: http.StatusServiceUnavailable}
	})

	// The operation error is returned unchanged, without another attempt.
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("error = %v, want the *HTTPError", err)
	}

	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
}

func TestRetryablePropagatesContextError(t *testing.T) {
	t.Parallel()

	client := &Client{retry: retryPolicy{maxAttempts: 3, backoff: time.Millisecond, maxBackoff: time.Millisecond}}

	err := client.retryable(t.Context(), "test", func() error {
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
