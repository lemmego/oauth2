package oauth2

import (
	"crypto/rsa"
	"github.com/lemmego/api/app"
	"net/url"
	"sync"
	"testing"
	"time"
)

// One key for the whole package's tests. Generating a 2048-bit RSA key costs
// enough that doing it per test would dominate the run.
var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
)

func sharedTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		key, err := GenerateKey(2048)
		if err != nil {
			panic(err)
		}
		testKey = key
	})
	return testKey
}

// clock is a time source a test advances by hand, so expiry is exercised
// without sleeping and a test cannot be flaky because a machine was busy.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock {
	return &clock{now: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type harness struct {
	t      *testing.T
	server *Server
	store  Store
	clock  *clock
}

func newHarness(t *testing.T, configure ...func(*Config)) *harness {
	t.Helper()

	cfg := DefaultConfig()
	cfg.Issuer = "https://auth.example.com"
	cfg.Scopes = map[string]string{
		"read":   "Read your things",
		"write":  "Change your things",
		"admin":  "Do anything",
		"orders": "See your orders",
	}
	for _, fn := range configure {
		fn(cfg)
	}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}

	c := newClock()
	store := NewMemoryStore()
	server, err := NewServerWithKeys(cfg, store,
		StaticKeySource{Keys: []*rsa.PrivateKey{sharedTestKey(t)}},
		WithClock(c.Now))
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, server: server, store: store, clock: c}
}

// confidentialClient registers a client with a known secret.
func (h *harness) confidentialClient(id string, grants ...string) (*Client, string) {
	h.t.Helper()
	secret, err := randomToken(32)
	if err != nil {
		h.t.Fatal(err)
	}
	client := &Client{
		ID:           id,
		Name:         id,
		SecretHash:   HashSecret(secret),
		RedirectURIs: []string{"https://app.example.com/cb"},
		GrantTypes:   grants,
		Confidential: true,
		CreatedAt:    h.clock.Now(),
		UpdatedAt:    h.clock.Now(),
	}
	if err := h.store.CreateClient(ctxOf(h.t), client); err != nil {
		h.t.Fatal(err)
	}
	return client, secret
}

func (h *harness) publicClient(id string, grants ...string) *Client {
	h.t.Helper()
	client := &Client{
		ID:           id,
		Name:         id,
		RedirectURIs: []string{"https://app.example.com/cb"},
		GrantTypes:   grants,
		Confidential: false,
		CreatedAt:    h.clock.Now(),
		UpdatedAt:    h.clock.Now(),
	}
	if err := h.store.CreateClient(ctxOf(h.t), client); err != nil {
		h.t.Fatal(err)
	}
	return client
}

// authorize runs an authorization and returns the issued code.
func (h *harness) authorize(client *Client, verifier string, scope string) string {
	h.t.Helper()
	params := url.Values{
		"client_id":             {client.ID},
		"response_type":         {"code"},
		"redirect_uri":          {"https://app.example.com/cb"},
		"scope":                 {scope},
		"code_challenge":        {ChallengeFor(verifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
	}
	request, err := h.server.ParseAuthorizeRequest(ctxOf(h.t), params)
	if err != nil {
		h.t.Fatalf("authorize: %v", err)
	}
	code, err := h.server.GrantAuthorization(ctxOf(h.t), request, "user-1", nil)
	if err != nil {
		h.t.Fatalf("granting: %v", err)
	}
	return code
}

// exchange redeems a code.
func (h *harness) exchange(client *Client, secret, code, verifier string) (*TokenResponse, error) {
	h.t.Helper()
	return h.server.Token(ctxOf(h.t), "", url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"client_id":     {client.ID},
		"client_secret": {secret},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/cb"},
		"code_verifier": {verifier},
	})
}

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func ctxOf(t *testing.T) Context {
	t.Helper()
	return t.Context()
}

// sessionContext is the little of app.Context the management forms touch: a
// per-request bag and a session that outlives the request.
type sessionContext struct {
	app.Context
	values  map[string]any
	session map[string]any
}

func newSessionContext() *sessionContext {
	return &sessionContext{values: map[string]any{}, session: map[string]any{}}
}

func (c *sessionContext) Set(key string, value any) { c.values[key] = value }
func (c *sessionContext) Get(key string) any        { return c.values[key] }
func (c *sessionContext) Session(key string) any    { return c.session[key] }
func (c *sessionContext) PopSession(key string) any {
	value := c.session[key]
	delete(c.session, key)
	return value
}

func (c *sessionContext) PutSession(key string, value any) app.SessionGetSetter {
	c.session[key] = value
	return nil
}
