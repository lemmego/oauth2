package oauth2

import (
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// The happy path first, so a failure below means the attack was not blocked
// rather than that nothing works at all.
func TestAuthorizationCodeFlow(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)

	code := h.authorize(client, testVerifier, "read write")
	response, err := h.exchange(client, secret, code, testVerifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if response.AccessToken == "" || response.RefreshToken == "" {
		t.Fatal("the exchange returned no tokens")
	}
	if response.TokenType != "Bearer" {
		t.Errorf("token_type = %q", response.TokenType)
	}
	if response.Scope != "read write" {
		t.Errorf("scope = %q, want the granted scopes", response.Scope)
	}

	principal, err := h.server.Verify(ctxOf(t), response.AccessToken)
	if err != nil {
		t.Fatalf("the issued token does not verify: %v", err)
	}
	if principal.UserID != "user-1" || principal.ClientID != "app" {
		t.Errorf("principal = %+v", principal)
	}
	if !principal.HasAllScopes("read", "write") {
		t.Errorf("scopes = %v", principal.Scopes)
	}
}

// RFC 6749 section 4.1.2: a replayed code must be denied, and everything
// issued from it revoked, because a replay means the code leaked.
func TestCodeReplayRevokesTheFamily(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)

	code := h.authorize(client, testVerifier, "read")
	first, err := h.exchange(client, secret, code, testVerifier)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.exchange(client, secret, code, testVerifier); err == nil {
		t.Fatal("a replayed authorization code was accepted")
	}

	// The token from the first, legitimate exchange must now be dead too:
	// the server cannot tell which holder was the attacker.
	if _, err := h.server.Verify(ctxOf(t), first.AccessToken); err == nil {
		t.Error("the token issued from a replayed code still verifies")
	}
}

// Client B redeeming a code issued to client A is the code substitution
// attack.
func TestCodeSubstitutionAcrossClients(t *testing.T) {
	h := newHarness(t)
	victim, _ := h.confidentialClient("victim", GrantAuthorizationCode, GrantRefreshToken)
	attacker, attackerSecret := h.confidentialClient("attacker", GrantAuthorizationCode, GrantRefreshToken)

	code := h.authorize(victim, testVerifier, "read")
	if _, err := h.exchange(attacker, attackerSecret, code, testVerifier); err == nil {
		t.Fatal("a code issued to one client was redeemed by another")
	}
}

// The redirect at exchange time must be the one bound to the code, or a code
// stolen through one redirect can be redeemed through another.
func TestRedirectURISubstitutionAtExchange(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)
	client.RedirectURIs = append(client.RedirectURIs, "https://app.example.com/other")
	if err := h.store.UpdateClient(ctxOf(t), client); err != nil {
		t.Fatal(err)
	}

	code := h.authorize(client, testVerifier, "read")
	_, err := h.server.Token(ctxOf(t), "", url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"client_id":     {client.ID},
		"client_secret": {secret},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/other"},
		"code_verifier": {testVerifier},
	})
	if err == nil {
		t.Fatal("a code was redeemed against a redirect it was not bound to")
	}
}

func TestPKCEIsEnforcedEndToEnd(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)

	t.Run("a wrong verifier is rejected", func(t *testing.T) {
		code := h.authorize(client, testVerifier, "read")
		other := strings.Repeat("z", 43)
		if _, err := h.exchange(client, secret, code, other); err == nil {
			t.Fatal("a wrong code_verifier was accepted")
		}
	})

	t.Run("a stripped verifier is rejected", func(t *testing.T) {
		code := h.authorize(client, testVerifier, "read")
		if _, err := h.exchange(client, secret, code, ""); err == nil {
			t.Fatal("omitting code_verifier bypassed PKCE")
		}
	})

	t.Run("the challenge presented as the verifier is rejected", func(t *testing.T) {
		code := h.authorize(client, testVerifier, "read")
		if _, err := h.exchange(client, secret, code, ChallengeFor(testVerifier)); err == nil {
			t.Fatal("the challenge was accepted as its own verifier")
		}
	})

	t.Run("authorization without a challenge is refused", func(t *testing.T) {
		_, err := h.server.ParseAuthorizeRequest(ctxOf(t), url.Values{
			"client_id":     {client.ID},
			"response_type": {"code"},
			"redirect_uri":  {"https://app.example.com/cb"},
			"scope":         {"read"},
		})
		if err == nil {
			t.Fatal("an authorization with no code_challenge was accepted while PKCE is required")
		}
	})
}

// A public client has no secret, so PKCE is the only thing binding the code
// to the requester and cannot be optional for it.
func TestPublicClientAlwaysNeedsPKCE(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.RequirePKCE = false })
	client := h.publicClient("spa", GrantAuthorizationCode)

	_, err := h.server.ParseAuthorizeRequest(ctxOf(t), url.Values{
		"client_id":     {client.ID},
		"response_type": {"code"},
		"redirect_uri":  {"https://app.example.com/cb"},
		"scope":         {"read"},
	})
	if err == nil {
		t.Fatal("a public client authorized without PKCE even though it has no secret")
	}
}

// RFC 6819 section 5.2.2.3: presenting a rotated refresh token revokes the
// whole chain, including the successor the honest client holds.
func TestRefreshReuseRevokesTheFamily(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)

	code := h.authorize(client, testVerifier, "read")
	first, err := h.exchange(client, secret, code, testVerifier)
	if err != nil {
		t.Fatal(err)
	}

	second, err := h.refresh(client, secret, first.RefreshToken, "")
	if err != nil {
		t.Fatalf("a legitimate rotation failed: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("rotation returned the same refresh token")
	}

	// Replaying the spent token.
	if _, err := h.refresh(client, secret, first.RefreshToken, ""); err == nil {
		t.Fatal("a spent refresh token was accepted")
	}

	// Both the successor and its access token must now be dead.
	if _, err := h.refresh(client, secret, second.RefreshToken, ""); err == nil {
		t.Error("the successor survived a detected reuse")
	}
	if _, err := h.server.Verify(ctxOf(t), second.AccessToken); err == nil {
		t.Error("the access token survived a detected reuse")
	}
}

// RFC 6749 section 6: a refresh may narrow scopes and must never widen them.
func TestScopeElevationOnRefresh(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)

	code := h.authorize(client, testVerifier, "read")
	issued, err := h.exchange(client, secret, code, testVerifier)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.refresh(client, secret, issued.RefreshToken, "read write"); err == nil {
		t.Fatal("a refresh widened the granted scopes")
	}

	narrowed, err := h.refresh(client, secret, issued.RefreshToken, "read")
	if err != nil {
		t.Fatalf("narrowing was rejected: %v", err)
	}
	if narrowed.Scope != "read" {
		t.Errorf("scope = %q", narrowed.Scope)
	}
}

// A refresh token issued to one client must not be usable by another.
func TestRefreshTokenIsBoundToItsClient(t *testing.T) {
	h := newHarness(t)
	victim, victimSecret := h.confidentialClient("victim", GrantAuthorizationCode, GrantRefreshToken)
	attacker, attackerSecret := h.confidentialClient("attacker", GrantAuthorizationCode, GrantRefreshToken)

	code := h.authorize(victim, testVerifier, "read")
	issued, err := h.exchange(victim, victimSecret, code, testVerifier)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.refresh(attacker, attackerSecret, issued.RefreshToken, ""); err == nil {
		t.Fatal("another client used a refresh token it was not issued")
	}
	// And the theft must cost the victim their token, since the server has
	// to assume it leaked.
	if _, err := h.refresh(victim, victimSecret, issued.RefreshToken, ""); err == nil {
		t.Error("a refresh token survived being presented by another client")
	}
}

// Only one of several identical requests may win. A read-then-write
// implementation passes the single-threaded tests above and fails this one.
func TestConcurrentExchangeIssuesOneToken(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)
	code := h.authorize(client, testVerifier, "read")

	const racers = 16
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := h.exchange(client, secret, code, testVerifier); err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent exchanges succeeded, want exactly 1", succeeded, racers)
	}
}

// Every credential in the flow has a lifetime, and each must be enforced.
func TestExpiry(t *testing.T) {
	t.Run("authorization code", func(t *testing.T) {
		h := newHarness(t)
		client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)
		code := h.authorize(client, testVerifier, "read")

		h.clock.Advance(h.server.cfg.AuthCodeTTL + time.Second)
		if _, err := h.exchange(client, secret, code, testVerifier); err == nil {
			t.Fatal("an expired authorization code was accepted")
		}
	})

	t.Run("access token", func(t *testing.T) {
		h := newHarness(t)
		client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)
		code := h.authorize(client, testVerifier, "read")
		issued, err := h.exchange(client, secret, code, testVerifier)
		if err != nil {
			t.Fatal(err)
		}

		h.clock.Advance(h.server.cfg.AccessTokenTTL + time.Minute)
		if _, err := h.server.Verify(ctxOf(t), issued.AccessToken); err == nil {
			t.Fatal("an expired access token verified")
		}
	})

	t.Run("refresh token", func(t *testing.T) {
		h := newHarness(t)
		client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)
		code := h.authorize(client, testVerifier, "read")
		issued, err := h.exchange(client, secret, code, testVerifier)
		if err != nil {
			t.Fatal(err)
		}

		h.clock.Advance(h.server.cfg.RefreshTokenTTL + time.Hour)
		if _, err := h.refresh(client, secret, issued.RefreshToken, ""); err == nil {
			t.Fatal("an expired refresh token was accepted")
		}
	})
}

// Revoking has to take effect on the very next request, which is the only
// reason the verification path reads a row at all.
func TestRevocationTakesEffectImmediately(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)
	code := h.authorize(client, testVerifier, "read")
	issued, err := h.exchange(client, secret, code, testVerifier)
	if err != nil {
		t.Fatal(err)
	}

	principal, err := h.server.Verify(ctxOf(t), issued.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.RevokeAccessToken(ctxOf(t), principal.TokenID, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.server.Verify(ctxOf(t), issued.AccessToken); err == nil {
		t.Fatal("a revoked token still verifies")
	}
}

// Revoking a client has to kill its tokens, or "disconnect this application"
// means nothing.
func TestRevokingAClientKillsItsTokens(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)
	code := h.authorize(client, testVerifier, "read")
	issued, err := h.exchange(client, secret, code, testVerifier)
	if err != nil {
		t.Fatal(err)
	}

	if err := h.store.RevokeClient(ctxOf(t), client.ID, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.server.Verify(ctxOf(t), issued.AccessToken); err == nil {
		t.Fatal("a revoked client's token still verifies")
	}
}

func (h *harness) refresh(client *Client, secret, token, scope string) (*TokenResponse, error) {
	h.t.Helper()
	params := url.Values{
		"grant_type":    {GrantRefreshToken},
		"client_id":     {client.ID},
		"client_secret": {secret},
		"refresh_token": {token},
	}
	if scope != "" {
		params.Set("scope", scope)
	}
	return h.server.Token(ctxOf(h.t), "", params)
}
