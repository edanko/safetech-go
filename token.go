package safetech

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// tokenResponse is the subset of a Keycloak token response the client needs.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// cachedToken is an access token together with the time it was obtained.
type cachedToken struct {
	resp     tokenResponse
	obtained time.Time
}

// usable reports whether the token can be used for another request, keeping a
// safety margin below the advertised expiry.
func (t *cachedToken) usable(now time.Time) bool {
	if t.resp.AccessToken == "" || t.resp.ExpiresIn <= 0 {
		return false
	}

	lifetime := time.Duration(t.resp.ExpiresIn)*time.Second - tokenMargin

	return now.Before(t.obtained.Add(lifetime))
}

// tokenRefresh coordinates concurrent token acquisition: exactly one goroutine
// performs the token request while the others wait for its outcome.
type tokenRefresh struct {
	done chan struct{}
	err  error
}

// accessToken returns a valid access token, refreshing it or authenticating again
// as needed.
//
// A cached token is returned while holding the mutex only briefly, so concurrent
// requests never wait for a token round trip that someone else already made. The
// token request itself runs without the mutex.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	for {
		c.mu.Lock()

		if c.token != nil && c.token.usable(time.Now()) {
			accessToken := c.token.resp.AccessToken
			c.mu.Unlock()

			return accessToken, nil
		}

		if pending := c.refresh; pending != nil {
			c.mu.Unlock()

			select {
			case <-pending.done:
				if pending.err != nil {
					return "", pending.err
				}

				// The leader cached a token; loop and pick it up.
				continue
			case <-ctx.Done():
				return "", fmt.Errorf("safetech: obtain access token: %w", ctx.Err())
			}
		}

		call := &tokenRefresh{done: make(chan struct{})}
		c.refresh = call
		c.mu.Unlock()

		err := c.obtainToken(ctx)

		c.mu.Lock()
		call.err = err
		c.refresh = nil

		accessToken := ""
		if err == nil && c.token != nil {
			accessToken = c.token.resp.AccessToken
		}
		c.mu.Unlock()

		// Publish the outcome after the state is settled.
		close(call.done)

		if err != nil {
			return "", err
		}

		if accessToken == "" {
			return "", errors.New("safetech: obtain access token: token response is empty")
		}

		return accessToken, nil
	}
}

// obtainToken performs the token round trip: the refresh_token grant when a
// refresh token is cached, falling back to the password grant. It caches the
// result.
func (c *Client) obtainToken(ctx context.Context) error {
	endpoints, err := c.resolveAuthEndpoints(ctx)
	if err != nil {
		return err
	}

	c.mu.Lock()
	refreshToken := ""
	if c.token != nil {
		refreshToken = c.token.resp.RefreshToken
	}
	c.mu.Unlock()

	if refreshToken != "" {
		refreshed, err := c.requestToken(ctx, endpoints.tokenURL, url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {endpoints.clientID},
			"refresh_token": {refreshToken},
		})
		if err == nil {
			c.storeToken(refreshed)

			return nil
		}
		// Fall through to the password grant: the refresh token may have expired
		// or been revoked. Its error is not reported because the password grant
		// below is the authoritative attempt.
	}

	if c.cfg.Username == "" || c.cfg.Password == "" {
		return errors.New("safetech: Config.Username and Config.Password are required")
	}

	issued, err := c.requestToken(ctx, endpoints.tokenURL, url.Values{
		"grant_type": {"password"},
		"client_id":  {endpoints.clientID},
		"username":   {c.cfg.Username},
		"password":   {c.cfg.Password},
		"scope":      {"openid"},
	})
	if err != nil {
		return fmt.Errorf("safetech: obtain access token: %w", err)
	}

	c.storeToken(issued)

	return nil
}

// storeToken caches a freshly obtained token.
func (c *Client) storeToken(tok *tokenResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.token = &cachedToken{resp: *tok, obtained: time.Now()}
}

// resolveAuthEndpoints returns the Keycloak token endpoint and client id,
// discovering them on first use. Discovery performs network I/O, so it runs
// without holding c.mu.
func (c *Client) resolveAuthEndpoints(ctx context.Context) (*authEndpoints, error) {
	c.mu.Lock()
	cached := c.auth
	c.mu.Unlock()

	if cached != nil {
		return cached, nil
	}

	endpoints := &authEndpoints{clientID: cmp.Or(c.cfg.ClientID, defaultClientID)}

	if c.cfg.AuthURL != "" {
		endpoints.tokenURL = c.cfg.AuthURL + tokenPath
	} else {
		discovered, err := c.discoverAuth(ctx)
		if err != nil {
			return nil, err
		}

		endpoints = discovered
	}

	c.mu.Lock()
	c.auth = endpoints
	c.mu.Unlock()

	return endpoints, nil
}

// discoverAuth resolves the Keycloak token endpoint from the public
// /api/ui-config endpoint of the CA gateway, which advertises the URL, realm and
// client id used by the management web UI. Transient failures are retried
// according to Config.Retry.
func (c *Client) discoverAuth(ctx context.Context) (*authEndpoints, error) {
	var endpoints *authEndpoints

	err := c.retryable(ctx, "auth discovery", func() error {
		discovered, err := c.discoverAuthOnce(ctx)
		if err != nil {
			return err
		}

		endpoints = discovered

		return nil
	})
	if err != nil {
		return nil, err
	}

	return endpoints, nil
}

// discoverAuthOnce performs a single discovery request.
func (c *Client) discoverAuthOnce(ctx context.Context) (*authEndpoints, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+uiConfigPath, nil)
	if err != nil {
		return nil, fmt.Errorf("safetech: auth discovery: build request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("safetech: auth discovery: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxUIConfigBytes))
	if err != nil {
		return nil, fmt.Errorf("safetech: auth discovery: read response: %w", err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf(
			"safetech: auth discovery: set Config.AuthURL to skip it: %w",
			newHTTPError(resp.StatusCode, resp.Header, raw),
		)
	}

	var discovered struct {
		KeyCloak struct {
			Config struct {
				URL      string `json:"url"`
				Realm    string `json:"realm"`
				ClientID string `json:"clientId"`
			} `json:"config"`
		} `json:"keyCloak"`
	}

	if err := json.Unmarshal(raw, &discovered); err != nil {
		return nil, fmt.Errorf("safetech: auth discovery: decode response: %w", err)
	}

	realm := discovered.KeyCloak.Config
	if realm.URL == "" || realm.Realm == "" {
		return nil, errors.New(
			"safetech: auth discovery: incomplete realm configuration; set Config.AuthURL to skip discovery",
		)
	}

	return &authEndpoints{
		tokenURL: strings.TrimSuffix(realm.URL, "/") + "/realms/" + url.PathEscape(realm.Realm) + tokenPath,
		clientID: cmp.Or(c.cfg.ClientID, realm.ClientID, defaultClientID),
	}, nil
}

// requestToken performs a form POST against the Keycloak token endpoint,
// adding the client secret for confidential clients. Transient failures are
// retried according to Config.Retry.
func (c *Client) requestToken(ctx context.Context, tokenURL string, form url.Values) (*tokenResponse, error) {
	var token *tokenResponse

	err := c.retryable(ctx, "token request", func() error {
		issued, err := c.requestTokenOnce(ctx, tokenURL, form)
		if err != nil {
			return err
		}

		token = issued

		return nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}

// requestTokenOnce performs a single token request.
func (c *Client) requestTokenOnce(ctx context.Context, tokenURL string, form url.Values) (*tokenResponse, error) {
	form = form.Clone()

	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("safetech: build token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("safetech: token request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("safetech: read token response: %w", err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, newHTTPError(resp.StatusCode, resp.Header, raw)
	}

	var token tokenResponse
	if err := json.Unmarshal(raw, &token); err != nil {
		return nil, fmt.Errorf("safetech: decode token response: %w", err)
	}

	if token.AccessToken == "" {
		return nil, errors.New("safetech: token response has no access_token")
	}

	return &token, nil
}
