package oauth2

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func postTo(t *testing.T, handler http.HandlerFunc, body url.Values, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
}

func decodeBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	return body
}

func TestTokenEndpointReturnsATokenResponse(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)
	code := h.authorize(client, testVerifier, "read")

	recorder := postTo(t, h.server.HandleToken, url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"client_id":     {client.ID},
		"client_secret": {secret},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/cb"},
		"code_verifier": {testVerifier},
	}, "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	// RFC 6749 section 5.1: a token response must never be cached.
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	body := decodeBody(t, recorder)
	for _, field := range []string{"access_token", "token_type", "expires_in", "refresh_token"} {
		if _, ok := body[field]; !ok {
			t.Errorf("the response has no %s: %v", field, body)
		}
	}
}

// RFC 6749 section 5.2: the body must carry an "error" member, because a
// client library branches on its value. The framework's own error helpers
// render {"message": ...}, which would read as an unknown failure.
func TestTokenEndpointErrorsUseTheProtocolShape(t *testing.T) {
	h := newHarness(t)
	h.confidentialClient("app", GrantAuthorizationCode)

	recorder := postTo(t, h.server.HandleToken, url.Values{
		"grant_type": {"telepathy"},
		"client_id":  {"app"},
	}, "")

	body := decodeBody(t, recorder)
	if _, ok := body["message"]; ok {
		t.Error("the response uses the framework's error shape instead of the protocol's")
	}
	if body["error"] != ErrCodeInvalidClient && body["error"] != ErrCodeUnsupportedGrantType {
		t.Errorf("error = %v", body["error"])
	}
}

// An invalid_client answered with 401 must carry a challenge, or a client
// cannot tell authentication failed from the request being malformed.
func TestInvalidClientCarriesAChallenge(t *testing.T) {
	h := newHarness(t)
	h.confidentialClient("app", GrantAuthorizationCode)

	recorder := postTo(t, h.server.HandleToken, url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"client_id":     {"app"},
		"client_secret": {"wrong"},
		"code":          {"whatever"},
	}, "")

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	if recorder.Header().Get("WWW-Authenticate") == "" {
		t.Error("a 401 was sent with no WWW-Authenticate challenge")
	}
}

// A wrong method must be 405 with an Allow header. Registering a
// method-qualified pattern instead would let it fall through to the
// application's catch-all and answer 404, telling a client the endpoint does
// not exist.
func TestWrongMethodIs405WithAllow(t *testing.T) {
	h := newHarness(t)

	request := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	recorder := httptest.NewRecorder()
	h.server.HandleToken(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", recorder.Code)
	}
	if got := recorder.Header().Get("Allow"); got != http.MethodPost {
		t.Errorf("Allow = %q, want POST", got)
	}
}

// ParseForm merges the URL query into r.Form, so a server reading that would
// accept credentials in a query string — where they land in access logs,
// proxy logs and browser history.
func TestCredentialsInTheQueryStringAreIgnored(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantClientCredentials)

	query := url.Values{
		"grant_type":    {GrantClientCredentials},
		"client_id":     {client.ID},
		"client_secret": {secret},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth/token?"+query.Encode(), strings.NewReader(""))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	h.server.HandleToken(recorder, request)

	if recorder.Code == http.StatusOK {
		t.Fatal("client credentials supplied in the query string were accepted")
	}
}

func TestBasicAuthenticationIsAccepted(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantClientCredentials)

	request := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader(url.Values{"grant_type": {GrantClientCredentials}, "scope": {"read"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(client.ID, secret)

	recorder := httptest.NewRecorder()
	h.server.HandleToken(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
}

// RFC 6749 section 2.3 forbids more than one authentication method at once.
// Resolving the ambiguity by preference is how a server ends up
// authenticating one client while acting for another.
func TestCredentialsInBothPlacesAreRejected(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantClientCredentials)

	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(url.Values{
		"grant_type":    {GrantClientCredentials},
		"client_id":     {client.ID},
		"client_secret": {secret},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(client.ID, secret)

	recorder := httptest.NewRecorder()
	h.server.HandleToken(recorder, request)
	if recorder.Code == http.StatusOK {
		t.Fatal("credentials sent in both the header and the body were accepted")
	}
}

func TestJWKSIsCacheableAndCarriesAnETag(t *testing.T) {
	h := newHarness(t)

	request := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	recorder := httptest.NewRecorder()
	h.server.HandleJWKS(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	etag := recorder.Header().Get("ETag")
	if etag == "" {
		t.Fatal("the JWKS carries no ETag, so a rotation could not invalidate caches")
	}

	// A conditional request must be answered 304, or the ETag is decorative.
	conditional := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	conditional.Header.Set("If-None-Match", etag)
	second := httptest.NewRecorder()
	h.server.HandleJWKS(second, conditional)
	if second.Code != http.StatusNotModified {
		t.Errorf("a conditional request returned %d, want 304", second.Code)
	}
}

func TestMetadataAdvertisesOnlyWhatIsSupported(t *testing.T) {
	h := newHarness(t)

	request := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	recorder := httptest.NewRecorder()
	h.server.HandleMetadata(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	var metadata Metadata
	if err := json.Unmarshal(recorder.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}

	// Advertising only S256 is how a correct client learns not to attempt
	// plain, rather than discovering it through a rejected request.
	if len(metadata.CodeChallengeMethodsSupported) != 1 ||
		metadata.CodeChallengeMethodsSupported[0] != ChallengeMethodS256 {
		t.Errorf("code_challenge_methods_supported = %v", metadata.CodeChallengeMethodsSupported)
	}
	if len(metadata.ResponseTypesSupported) != 1 || metadata.ResponseTypesSupported[0] != "code" {
		t.Errorf("response_types_supported = %v; implicit must not be advertised",
			metadata.ResponseTypesSupported)
	}
	for _, grant := range metadata.GrantTypesSupported {
		if grant == "password" || grant == "implicit" {
			t.Errorf("a deprecated grant is advertised: %s", grant)
		}
	}
	if metadata.JWKSURI != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %q; RFC 8414 puts it at the root, not under the route prefix", metadata.JWKSURI)
	}
}

// RFC 7662 section 2.2: an inactive token returns exactly {"active": false}.
// Any additional field would tell a caller something about a token it could
// not otherwise verify.
func TestIntrospectionOfAnInactiveTokenSaysOnlyThat(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("resource", GrantClientCredentials)

	recorder := postTo(t, h.server.HandleIntrospect, url.Values{
		"client_id":     {client.ID},
		"client_secret": {secret},
		"token":         {"not-a-token"},
	}, "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	body := decodeBody(t, recorder)
	if body["active"] != false {
		t.Errorf("active = %v", body["active"])
	}
	if len(body) != 1 {
		t.Errorf("an inactive introspection leaked extra fields: %v", body)
	}
}

// A public client could otherwise use introspection to probe tokens it was
// never issued.
func TestIntrospectionRefusesPublicClients(t *testing.T) {
	h := newHarness(t)
	client := h.publicClient("spa", GrantAuthorizationCode)

	recorder := postTo(t, h.server.HandleIntrospect, url.Values{
		"client_id": {client.ID},
		"token":     {"anything"},
	}, "")
	if recorder.Code == http.StatusOK {
		t.Fatal("a public client was allowed to introspect")
	}
}

// RFC 7009 section 2.2: revocation reports success even for a token that was
// already invalid, because a client cannot know and distinguishing the cases
// would let anyone probe which tokens exist.
func TestRevocationIsIdempotentAndQuiet(t *testing.T) {
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)
	code := h.authorize(client, testVerifier, "read")
	issued, err := h.exchange(client, secret, code, testVerifier)
	if err != nil {
		t.Fatal(err)
	}

	for _, token := range []string{issued.RefreshToken, issued.RefreshToken, "never-existed"} {
		recorder := postTo(t, h.server.HandleRevoke, url.Values{
			"client_id":     {client.ID},
			"client_secret": {secret},
			"token":         {token},
		}, "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("revoking %q returned %d", token, recorder.Code)
		}
		if body, _ := io.ReadAll(recorder.Body); len(body) != 0 {
			t.Errorf("revocation returned a body: %s", body)
		}
	}

	if _, err := h.server.Verify(ctxOf(t), issued.AccessToken); err == nil {
		t.Error("revoking the refresh token left its access token live")
	}
}

// CORS on the token endpoint must never allow credentials: a browser client
// here is public and uses PKCE, not a cookie.
func TestTokenCORSNeverAllowsCredentials(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.CORSOrigins = []string{"https://spa.example.com"} })

	request := httptest.NewRequest(http.MethodOptions, "/oauth/token", nil)
	request.Header.Set("Origin", "https://spa.example.com")
	recorder := httptest.NewRecorder()
	h.server.corsPublic(http.HandlerFunc(h.server.HandleToken)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("preflight returned %d", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://spa.example.com" {
		t.Errorf("Allow-Origin = %q", got)
	}
	if recorder.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("the token endpoint allowed credentials")
	}
	// The response varies by origin, so a cache must not serve one origin's
	// response to another.
	if !strings.Contains(recorder.Header().Get("Vary"), "Origin") {
		t.Error("the response does not vary by Origin")
	}
}

func TestUnlistedOriginGetsNoCORSHeaders(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.CORSOrigins = []string{"https://spa.example.com"} })

	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(""))
	request.Header.Set("Origin", "https://evil.example.com")
	recorder := httptest.NewRecorder()
	h.server.corsPublic(http.HandlerFunc(h.server.HandleToken)).ServeHTTP(recorder, request)

	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("an unlisted origin was allowed")
	}
}
