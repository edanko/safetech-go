package safetech

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// seedToken installs a cached token without performing a token request.
func seedToken(t *testing.T, client *Client, resp tokenResponse, obtained time.Time) {
	t.Helper()

	client.mu.Lock()
	defer client.mu.Unlock()

	client.token = &cachedToken{resp: resp, obtained: obtained}
}

// seedAuth installs resolved auth endpoints, skipping discovery.
func seedAuth(client *Client, tokenURL string) {
	client.mu.Lock()
	defer client.mu.Unlock()

	client.auth = &authEndpoints{tokenURL: tokenURL, clientID: defaultClientID}
}

func TestCachedTokenUsable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.November, 18, 12, 0, 0, 0, time.UTC)

	tests := map[string]struct {
		token cachedToken
		want  bool
	}{
		"fresh": {
			token: cachedToken{resp: tokenResponse{AccessToken: "a", ExpiresIn: 300}, obtained: now},
			want:  true,
		},
		"expired": {
			token: cachedToken{resp: tokenResponse{AccessToken: "a", ExpiresIn: 300}, obtained: now.Add(-time.Hour)},
			want:  false,
		},
		"inside safety margin": {
			token: cachedToken{resp: tokenResponse{AccessToken: "a", ExpiresIn: 300}, obtained: now.Add(-285 * time.Second)},
			want:  false,
		},
		"just before safety margin": {
			token: cachedToken{resp: tokenResponse{AccessToken: "a", ExpiresIn: 300}, obtained: now.Add(-284 * time.Second)},
			want:  true,
		},
		"zero expiry": {
			token: cachedToken{resp: tokenResponse{AccessToken: "a"}, obtained: now},
			want:  false,
		},
		"negative expiry": {
			token: cachedToken{resp: tokenResponse{AccessToken: "a", ExpiresIn: -1}, obtained: now},
			want:  false,
		},
		"empty access token": {
			token: cachedToken{resp: tokenResponse{ExpiresIn: 300}, obtained: now},
			want:  false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := test.token.usable(now); got != test.want {
				t.Errorf("usable() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestAccessTokenCachesValue(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	client := f.newClient(t)

	first, err := client.accessToken(t.Context())
	if err != nil {
		t.Fatalf("accessToken: %v", err)
	}

	second, err := client.accessToken(t.Context())
	if err != nil {
		t.Fatalf("accessToken: %v", err)
	}

	if first != testAccessToken || second != testAccessToken {
		t.Errorf("tokens = %q, %q; want %q for both", first, second, testAccessToken)
	}

	if got := len(f.tokenForms()); got != 1 {
		t.Errorf("token requests = %d, want 1", got)
	}
}

func TestAccessTokenRefreshesExpiredToken(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	client := f.newClient(t)

	seedToken(t, client, tokenResponse{
		AccessToken:  "stale-token",
		ExpiresIn:    3600,
		RefreshToken: testRefreshToken,
	}, time.Now().Add(-2*time.Hour))
	seedAuth(client, f.authURL()+tokenPath)

	got, err := client.accessToken(t.Context())
	if err != nil {
		t.Fatalf("accessToken: %v", err)
	}

	if got != testAccessToken {
		t.Errorf("token = %q, want %q", got, testAccessToken)
	}

	forms := f.tokenForms()
	if len(forms) != 1 {
		t.Fatalf("token requests = %d, want 1", len(forms))
	}

	if grant := forms[0].Get("grant_type"); grant != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", grant)
	}

	if refresh := forms[0].Get("refresh_token"); refresh != testRefreshToken {
		t.Errorf("refresh_token = %q, want %q", refresh, testRefreshToken)
	}
}

func TestAccessTokenFallsBackToPasswordGrant(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	f.setRejectRefresh(true)

	client := f.newClient(t)

	seedToken(t, client, tokenResponse{
		AccessToken:  "stale-token",
		ExpiresIn:    3600,
		RefreshToken: testRefreshToken,
	}, time.Now().Add(-2*time.Hour))
	seedAuth(client, f.authURL()+tokenPath)

	got, err := client.accessToken(t.Context())
	if err != nil {
		t.Fatalf("accessToken: %v", err)
	}

	if got != testAccessToken {
		t.Errorf("token = %q, want %q", got, testAccessToken)
	}

	forms := f.tokenForms()
	if len(forms) != 2 {
		t.Fatalf("token requests = %d, want 2 (refresh, then password)", len(forms))
	}

	if grant := forms[0].Get("grant_type"); grant != "refresh_token" {
		t.Errorf("first grant_type = %q, want refresh_token", grant)
	}

	if grant := forms[1].Get("grant_type"); grant != "password" {
		t.Errorf("second grant_type = %q, want password", grant)
	}

	if username := forms[1].Get("username"); username != testUsername {
		t.Errorf("username = %q, want %q", username, testUsername)
	}
}

func TestAccessTokenRequiresCredentials(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	client := f.newClient(t, func(cfg *Config) {
		cfg.Username = ""
		cfg.Password = ""
	})

	seedAuth(client, f.authURL()+tokenPath)

	_, err := client.accessToken(t.Context())
	if err == nil || !strings.Contains(err.Error(), "Config.Username") {
		t.Fatalf("error = %v, want it to report missing credentials", err)
	}

	if got := len(f.tokenForms()); got != 0 {
		t.Errorf("token requests = %d, want 0", got)
	}
}

func TestAccessTokenSendsClientSecret(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	client := f.newClient(t, func(cfg *Config) {
		cfg.ClientSecret = "client-secret-value"
		cfg.ClientID = "confidential-client"
	})

	if _, err := client.accessToken(t.Context()); err != nil {
		t.Fatalf("accessToken: %v", err)
	}

	forms := f.tokenForms()
	if len(forms) != 1 {
		t.Fatalf("token requests = %d, want 1", len(forms))
	}

	if got := forms[0].Get("client_secret"); got != "client-secret-value" {
		t.Errorf("client_secret = %q, want %q", got, "client-secret-value")
	}

	if got := forms[0].Get("client_id"); got != "confidential-client" {
		t.Errorf("client_id = %q, want %q", got, "confidential-client")
	}
}

func TestAuthURLSkipsDiscovery(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	client := f.newClient(t, func(cfg *Config) {
		// A trailing slash must not produce a doubled separator.
		cfg.AuthURL = f.authURL() + "/"
	})

	if _, err := client.accessToken(t.Context()); err != nil {
		t.Fatalf("accessToken: %v", err)
	}

	if got := len(f.requestsTo(uiConfigPath)); got != 0 {
		t.Errorf("ui-config requests = %d, want 0 when Config.AuthURL is set", got)
	}

	forms := f.tokenForms()
	if len(forms) != 1 {
		t.Fatalf("token requests = %d, want 1", len(forms))
	}

	if got := forms[0].Get("client_id"); got != defaultClientID {
		t.Errorf("client_id = %q, want the %q default", got, defaultClientID)
	}
}

func TestDiscoveryFailureSuggestsAuthURL(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	f.setHandler(uiConfigPath, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	_, err := f.newClient(t).accessToken(t.Context())
	if err == nil {
		t.Fatal("expected an error")
	}

	if !strings.Contains(err.Error(), "Config.AuthURL") {
		t.Errorf("error = %q, want it to suggest Config.AuthURL", err)
	}

	if _, ok := errors.AsType[*HTTPError](err); !ok {
		t.Errorf("error = %v, want it to wrap an *HTTPError", err)
	}
}

func TestDiscoveryIncompleteRealmFails(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	f.setHandler(uiConfigPath, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"keyCloak": map[string]any{
				"config": map[string]any{"clientId": defaultClientID},
			},
		})
	})

	_, err := f.newClient(t).accessToken(t.Context())
	if err == nil || !strings.Contains(err.Error(), "incomplete realm configuration") {
		t.Fatalf("error = %v, want it to report an incomplete realm configuration", err)
	}
}

func TestTokenErrorDoesNotLeakPassword(t *testing.T) {
	t.Parallel()

	f := newFakeCA(t)
	f.setHandler("/realms/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_grant"})
	})

	client := f.newClient(t)
	seedAuth(client, f.authURL()+tokenPath)

	_, err := client.accessToken(t.Context())
	if err == nil {
		t.Fatal("expected an error")
	}

	if strings.Contains(err.Error(), testPassword) {
		t.Errorf("error %q leaks the configured password", err)
	}

	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %q, want it to report the HTTP status", err)
	}
}
