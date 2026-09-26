package oauth2

import (
	"strings"
	"testing"
)

// The page lists the signed-in user's own clients and nobody else's. That is
// what makes it safe without an administrator role: a page showing every
// client would leak the existence of every integration to anyone who reached
// it.
func TestClientsAreScopedToTheirOwner(t *testing.T) {
	h := newHarness(t)

	mine := &Client{
		ID: "mine", UserID: "user-1", Name: "Mine",
		GrantTypes: []string{GrantClientCredentials}, Confidential: true,
	}
	theirs := &Client{
		ID: "theirs", UserID: "user-2", Name: "Theirs",
		GrantTypes: []string{GrantClientCredentials}, Confidential: true,
	}
	for _, client := range []*Client{mine, theirs} {
		if err := h.store.CreateClient(ctxOf(t), client); err != nil {
			t.Fatal(err)
		}
	}

	listed, err := h.store.ClientsForUser(ctxOf(t), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != "mine" {
		t.Fatalf("the page would show %d clients: %v", len(listed), listed)
	}
}

// The token is stored in the session and compared, not re-derived.
//
// An earlier version derived it from the session id, which does not exist
// yet on the GET that creates the session — so it never matched on the POST
// and every registration was rejected as a stale form. That only showed up
// when the page was driven through a browser flow with a cookie jar.
func TestFormTokenIsStoredAndCompared(t *testing.T) {
	c := newSessionContext()

	token, err := issueFormToken(c)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("no token was issued")
	}
	if !checkFormToken(c, token) {
		t.Fatal("the issued token did not verify against the session that stored it")
	}

	// Stable across requests in the same session, so several open tabs keep
	// working.
	again, err := issueFormToken(c)
	if err != nil {
		t.Fatal(err)
	}
	if again != token {
		t.Error("a second request minted a different token, which would break a second tab")
	}

	if checkFormToken(c, "") {
		t.Error("an empty token was accepted")
	}
	if checkFormToken(c, "forged") {
		t.Error("a forged token was accepted")
	}
	if checkFormToken(newSessionContext(), token) {
		t.Error("a token from one session verified against another")
	}
}

// The registration form has to reject a redirect URI that would be dangerous
// once registered, since matching afterwards is faithful by design.
func TestRegistrationFormRejectsDangerousRedirects(t *testing.T) {
	for _, uri := range []string{
		"http://app.example.com/cb",          // plaintext to a public host
		"https://app.example.com/cb#frag",    // carries a fragment
		"https://user:pw@app.example.com/cb", // carries userinfo
		"/relative",                          // not absolute
	} {
		if err := ValidateRedirectURI(uri); err == nil {
			t.Errorf("the form would have accepted %q", uri)
		}
	}
}

// The page renders, and the markup carries what the handlers check.
func TestClientsPageRendersItsTokens(t *testing.T) {
	var builder strings.Builder
	err := renderClients(&builder, ClientsData{
		Clients: []ClientRow{{
			ID: "abc", Name: "Demo", GrantTypes: []string{GrantAuthorizationCode},
			RedirectURIs: []string{"https://app.example.com/cb"},
		}},
		CreateAction: "/oauth/clients",
		RevokeAction: "/oauth/clients/revoke",
		CSRFToken:    "csrf-value",
		FormToken:    "form-value",
	})
	if err != nil {
		t.Fatal(err)
	}
	page := builder.String()

	for _, want := range []string{
		`name="_token" value="csrf-value"`,
		`name="_oauth_form" value="form-value"`,
		`action="/oauth/clients"`,
		`action="/oauth/clients/revoke"`,
		"Demo",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not contain %q", want)
		}
	}
}

// A secret is stored hashed and cannot be recovered, so the page must show it
// once and never again. It reaches the page through a one-time session value.
func TestSecretIsRenderedOnlyWhenPresent(t *testing.T) {
	var withSecret, without strings.Builder
	if err := renderClients(&withSecret, ClientsData{NewClientID: "abc", NewSecret: "s3cret"}); err != nil {
		t.Fatal(err)
	}
	if err := renderClients(&without, ClientsData{}); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(withSecret.String(), "s3cret") {
		t.Error("the secret was not shown on the page that just created it")
	}
	if strings.Contains(without.String(), "s3cret") {
		t.Error("the secret leaked onto a page that did not create it")
	}
	if !strings.Contains(withSecret.String(), "only time the secret can be shown") {
		t.Error("the page does not warn that the secret cannot be recovered")
	}
}

// A public client has no secret, and the page must say so rather than
// showing an empty box where one would be.
func TestPublicClientRegistrationSaysItHasNoSecret(t *testing.T) {
	var builder strings.Builder
	if err := renderClients(&builder, ClientsData{NewClientID: "abc"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(builder.String(), "public client") {
		t.Error("the page does not explain that a public client has no secret")
	}
}
