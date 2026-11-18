package safetech

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// RetryPolicy controls how the client retries idempotent requests — token
// requests, endpoint discovery and GET operations — after a transient failure.
// Requests that issue or revoke certificates are never retried, because the CA
// gives no way to make them idempotent.
//
// The zero value retries twice (three attempts in total) with an exponential
// backoff starting at 200ms and capped at 5s.
type RetryPolicy struct {
	// Disabled turns retries off: every request is attempted once.
	Disabled bool
	// MaxAttempts is the total number of attempts, including the first. Zero
	// selects the default of 3.
	MaxAttempts int
	// Backoff is the wait before the second attempt; it doubles for each
	// further attempt. Zero selects the default of 200ms.
	Backoff time.Duration
	// MaxBackoff caps a single wait, including one requested by the server's
	// Retry-After header. Zero selects the default of 5s.
	MaxBackoff time.Duration
}

// Retry tuning defaults.
const (
	defaultRetryAttempts   = 3
	defaultRetryBackoff    = 200 * time.Millisecond
	defaultMaxRetryBackoff = 5 * time.Second
)

// retryPolicy is the normalised form of [RetryPolicy].
type retryPolicy struct {
	maxAttempts int
	backoff     time.Duration
	maxBackoff  time.Duration
}

// newRetryPolicy normalises a [RetryPolicy], applying the documented defaults.
func newRetryPolicy(policy RetryPolicy) retryPolicy {
	attempts := policy.MaxAttempts
	switch {
	case policy.Disabled:
		attempts = 1
	case attempts == 0:
		attempts = defaultRetryAttempts
	case attempts < 0:
		attempts = 1
	}

	return retryPolicy{
		maxAttempts: attempts,
		backoff:     cmp.Or(policy.Backoff, defaultRetryBackoff),
		maxBackoff:  cmp.Or(policy.MaxBackoff, defaultMaxRetryBackoff),
	}
}

// retryable runs operation until it succeeds, the attempts are exhausted, the
// error is not retryable, or ctx is done.
//
// Only idempotent operations may be wrapped: the caller must not pass a function
// that issues or revokes a certificate.
func (c *Client) retryable(ctx context.Context, operation string, fn func() error) error {
	var err error

	for attempt := 1; ; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}

		if attempt >= c.retry.maxAttempts || ctx.Err() != nil || !isRetryable(err) {
			return err
		}

		delay := c.retryDelay(attempt, err)

		timer := time.NewTimer(delay)

		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()

			return fmt.Errorf("safetech: %s: %w", operation, ctx.Err())
		}
	}
}

// retryDelay returns the wait before the next attempt: exponential backoff,
// capped, and replaced by a shorter server-provided hint.
func (c *Client) retryDelay(attempt int, err error) time.Duration {
	delay := c.retry.backoff << min(attempt-1, 8)

	if delay <= 0 || delay > c.retry.maxBackoff {
		delay = c.retry.maxBackoff
	}

	if hint := retryAfterHint(err); hint > 0 {
		delay = min(hint, c.retry.maxBackoff)
	}

	return delay
}

// retryAfterHint returns the delay the server asked for, if any.
func retryAfterHint(err error) time.Duration {
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		return 0
	}

	return httpErr.RetryAfter
}

// isRetryable reports whether err is worth another attempt: a transport failure,
// or a response the server itself marks as transient.
func isRetryable(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// A certificate the client does not trust will not become trusted by
	// retrying, so report the misconfiguration immediately.
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return false
	}

	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
		return false
	}

	if _, ok := errors.AsType[x509.HostnameError](err); ok {
		return false
	}

	if _, ok := errors.AsType[x509.CertificateInvalidError](err); ok {
		return false
	}

	if httpErr, ok := errors.AsType[*HTTPError](err); ok {
		return httpErr.StatusCode == http.StatusTooManyRequests ||
			httpErr.StatusCode >= http.StatusInternalServerError
	}

	// Transport-level failures: connection refused, DNS, TLS, timeouts.
	if _, ok := errors.AsType[*url.Error](err); ok {
		return true
	}

	_, ok := errors.AsType[net.Error](err)

	return ok
}
