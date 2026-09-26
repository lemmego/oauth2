package oauth2

import "testing"

// Every entry here is a near miss that some implementation somewhere has
// accepted. Exact string equality is the only rule, with loopback ports the
// single documented exception.
func TestRedirectURIMatching(t *testing.T) {
	registered := []string{"https://app.example.com/cb"}

	for _, tc := range []struct {
		requested string
		want      bool
		why       string
	}{
		{"https://app.example.com/cb", true, "the registered URI itself"},
		{"https://app.example.com/cb/", false, "a trailing slash is a different path"},
		{"https://app.example.com/cb/extra", false, "a subpath is not a prefix match"},
		{"https://app.example.com/cb?x=1", false, "an added query is a different URI"},
		{"https://app.example.com/cb#f", false, "an added fragment is a different URI"},
		{"https://app.example.com/cb/../other", false, "traversal must not normalise into a match"},
		{"https://app.example.com.evil.test/cb", false, "a suffixed host is a different host"},
		{"https://evil.test/cb", false, "a different host entirely"},
		{"https://app.example.com@evil.test/cb", false, "userinfo that reads as the registered host"},
		{"https://APP.EXAMPLE.COM/cb", false, "case differences are not normalised away"},
		{"http://app.example.com/cb", false, "a downgraded scheme"},
		{"//app.example.com/cb", false, "a scheme-relative URI"},
		{"https://app.example.com/%63b", false, "a percent-encoded path that decodes to a match"},
		{"", false, "an empty redirect"},
	} {
		if got := matchRedirectURI(registered, tc.requested); got != tc.want {
			t.Errorf("matchRedirectURI(%q) = %v, want %v (%s)", tc.requested, got, tc.want, tc.why)
		}
	}
}

// RFC 8252 section 7.3: a native application cannot know which ephemeral port
// it will be given, so the port alone may differ — and only for a literal
// loopback address.
func TestLoopbackRedirectIgnoresOnlyThePort(t *testing.T) {
	registered := []string{"http://127.0.0.1:1234/cb"}

	for _, tc := range []struct {
		requested string
		want      bool
		why       string
	}{
		{"http://127.0.0.1:1234/cb", true, "the same port"},
		{"http://127.0.0.1:55555/cb", true, "a different ephemeral port"},
		{"http://127.0.0.1/cb", true, "no port"},
		{"http://127.0.0.1:55555/other", false, "a different path"},
		{"https://127.0.0.1:1234/cb", false, "a different scheme"},
		{"http://127.0.0.2:1234/cb", false, "a different address"},
		{"http://localhost:1234/cb", false, "localhost resolves through the resolver and can be redirected"},
		{"http://127.0.0.1:1234/cb?x=1", false, "an added query"},
	} {
		if got := matchRedirectURI(registered, tc.requested); got != tc.want {
			t.Errorf("matchRedirectURI(%q) = %v, want %v (%s)", tc.requested, got, tc.want, tc.why)
		}
	}

	// A non-loopback registration must not gain port flexibility.
	if matchRedirectURI([]string{"https://app.example.com:443/cb"}, "https://app.example.com:8443/cb") {
		t.Error("a non-loopback redirect accepted a different port")
	}
}

func TestRegistrationRejectsDangerousRedirects(t *testing.T) {
	for _, tc := range []struct {
		uri string
		why string
	}{
		{"/cb", "relative"},
		{"https://app.example.com/cb#frag", "carries a fragment"},
		{"https://user:pass@app.example.com/cb", "carries userinfo"},
		{"https://app.example.com@evil.test/cb", "userinfo that reads as a host"},
		{"http://app.example.com/cb", "plaintext http to a non-loopback host"},
		{"not a uri at all", "not a URI"},
	} {
		if err := ValidateRedirectURI(tc.uri); err == nil {
			t.Errorf("ValidateRedirectURI(%q) accepted a URI that %s", tc.uri, tc.why)
		}
	}

	for _, uri := range []string{
		"https://app.example.com/cb",
		"http://127.0.0.1:1234/cb",
		"http://[::1]:1234/cb",
		"com.example.app:/oauth2redirect",
	} {
		if err := ValidateRedirectURI(uri); err != nil {
			t.Errorf("ValidateRedirectURI(%q) rejected a legitimate URI: %v", uri, err)
		}
	}
}
