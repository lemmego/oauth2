package oauth2

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lemmego/api/app"
	"github.com/lemmego/auth"
)

// protectContext is the little of app.Context that Protect touches.
type protectContext struct {
	app.Context
	req     *http.Request
	values  map[string]any
	status  int
	headers http.Header
}

func newProtectContext(header string) *protectContext {
	req := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	return &protectContext{req: req, values: map[string]any{}, headers: http.Header{}}
}

func (c *protectContext) Request() *http.Request { return c.req }
func (c *protectContext) Header(k string) string { return c.req.Header.Get(k) }
func (c *protectContext) Set(k string, v any)    { c.values[k] = v }
func (c *protectContext) Get(k string) any       { return c.values[k] }
func (c *protectContext) SetHeader(k, v string) app.HeaderGetSetter {
	c.headers.Set(k, v)
	return nil
}
func (c *protectContext) Next() error { return nil }
func (c *protectContext) RequestContext() Context {
	return c.req.Context()
}

// A user token records its subject with auth rather than inventing a user.
// auth's loader then produces the application's own type, so a handler behind
// a bearer token sees what it sees behind a session.
func TestProtectRecordsTheSubjectForAuth(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantClientCredentials)
	_ = secret

	access := &AccessToken{
		ID: "jti-1", UserID: "42", ClientID: client.ID,
		Scopes: Scopes{"read"}, FamilyID: "fam-1",
		ExpiresAt: h.clock.Now().Add(time.Hour), CreatedAt: h.clock.Now(),
	}
	if err := h.store.CreateAccessToken(ctxOf(t), access); err != nil {
		t.Fatal(err)
	}
	signed, err := h.server.signAccessToken(access)
	if err != nil {
		t.Fatal(err)
	}

	provider := &Provider{}
	provider.server = h.server

	c := newProtectContext("Bearer " + signed)
	if err := provider.Protect("read")(c); err != nil {
		t.Fatalf("Protect: %v", err)
	}

	if got, _ := c.Get(auth.UserIDKey).(string); got != "42" {
		t.Errorf("auth was handed subject %q, want %q", got, "42")
	}
	// The principal stays under its own key, not auth's.
	if c.Get(auth.UserKey) != nil {
		t.Errorf("a user was invented under auth's key: %#v", c.Get(auth.UserKey))
	}
	if _, ok := PrincipalFrom(c); !ok {
		t.Error("the principal is not reachable")
	}
}

// A client-credentials token is a machine acting as itself. Marking it
// authenticated is the truth; putting a *Principal under auth's user key was
// the old behaviour, and it falsified the one promise auth makes.
func TestProtectMarksClientCredentialsAuthenticatedWithoutAUser(t *testing.T) {
	h := newHarness(t)
	client, _ := h.confidentialClient("machine", GrantClientCredentials)

	access := &AccessToken{
		ID: "jti-2", ClientID: client.ID, Scopes: Scopes{"read"},
		FamilyID: "fam-2", ExpiresAt: h.clock.Now().Add(time.Hour), CreatedAt: h.clock.Now(),
	}
	if err := h.store.CreateAccessToken(ctxOf(t), access); err != nil {
		t.Fatal(err)
	}
	signed, err := h.server.signAccessToken(access)
	if err != nil {
		t.Fatal(err)
	}

	provider := &Provider{}
	provider.server = h.server

	c := newProtectContext("Bearer " + signed)
	if err := provider.Protect("read")(c); err != nil {
		t.Fatalf("Protect: %v", err)
	}

	if c.Get(auth.UserKey) != nil {
		t.Errorf("a machine token produced a user: %#v", c.Get(auth.UserKey))
	}
	if !auth.IsAuthenticated(c) {
		t.Error("a valid machine token was not treated as authenticated")
	}
	principal, ok := PrincipalFrom(c)
	if !ok || !principal.IsClientCredentials() {
		t.Error("the principal does not report a client-credentials token")
	}
}
