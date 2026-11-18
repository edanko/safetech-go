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

// accessToken returns a valid access token, refreshing it or authenticating
// again as needed. It must be called without c.mu held.
//
// The mutex is held across the token requests on purpose: it makes a burst of
// concurrent calls perform at most one token request.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != nil && c.token.usable(time.Now()) {
		return c.token.resp.AccessToken, nil
	}

	endpoints, err := c.authEndpointsLocked(ctx)
	if err != nil {
		return "", fmt.Errorf("safetech: obtain access token: %w", err)
	}

	if c.token != nil && c.token.resp.RefreshToken != "" {
		refreshed, err := c.requestToken(ctx, endpoints.tokenURL, url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {endpoints.clientID},
			"refresh_token": {c.token.resp.RefreshToken},
		})
		if err == nil {
			c.token = &cachedToken{resp: *refreshed, obtained: time.Now()}

			return refreshed.AccessToken, nil
		}
		// Fall through to the password grant: the refresh token may have
		// expired or been revoked. Its error is not reported because the
		// password grant below is the authoritative attempt.
	}

	if c.cfg.Username == "" || c.cfg.Password == "" {
		return "", errors.New("safetech: Config.Username and Config.Password are required")
	}

	issued, err := c.requestToken(ctx, endpoints.tokenURL, url.Values{
		"grant_type": {"password"},
		"client_id":  {endpoints.clientID},
		"username":   {c.cfg.Username},
		"password":   {c.cfg.Password},
		"scope":      {"openid"},
	})
	if err != nil {
		return "", fmt.Errorf("safetech: obtain access token: %w", err)
	}

	c.token = &cachedToken{resp: *issued, obtained: time.Now()}

	return issued.AccessToken, nil
}

// authEndpointsLocked resolves the Keycloak token endpoint and OIDC client id,
// discovering them on demand. It must be called with c.mu held.
func (c *Client) authEndpointsLocked(ctx context.Context) (*authEndpoints, error) {
	if c.auth != nil {
		return c.auth, nil
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

	c.auth = endpoints

	return endpoints, nil
}

// discoverAuth resolves the Keycloak token endpoint from the public
// /api/ui-config endpoint of the CA gateway, which advertises the URL, realm and
// client id used by the management web UI.
func (c *Client) discoverAuth(ctx context.Context) (*authEndpoints, error) {
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
			newHTTPError(resp.StatusCode, raw),
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
// adding the client secret for confidential clients.
func (c *Client) requestToken(ctx context.Context, tokenURL string, form url.Values) (*tokenResponse, error) {
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
		return nil, newHTTPError(resp.StatusCode, raw)
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
