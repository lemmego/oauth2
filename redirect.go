package oauth2

import (
	"net"
	"net/url"
	"strings"
)

// matchRedirectURI reports whether a requested redirect is one the client
// registered.
//
// Comparison is exact string equality. Not a prefix, not a subpath, no
// wildcards: every one of those has been the root cause of a real token
// theft, and RFC 9700 section 2.1 says simple string comparison.
//
// The one exception is RFC 8252 section 7.3 loopback redirection, where a
// native application cannot know in advance which ephemeral port it will be
// given. For 127.0.0.1 and [::1] the port is ignored and everything else
// still has to match exactly.
func matchRedirectURI(registered []string, requested string) bool {
	for _, candidate := range registered {
		if candidate == requested {
			return true
		}
		if loopbackMatch(candidate, requested) {
			return true
		}
	}
	return false
}

func loopbackMatch(registered, requested string) bool {
	a, err := url.Parse(registered)
	if err != nil {
		return false
	}
	b, err := url.Parse(requested)
	if err != nil {
		return false
	}
	if !isLoopbackHost(a.Hostname()) || !isLoopbackHost(b.Hostname()) {
		return false
	}
	// Everything but the port must still be identical.
	return a.Scheme == b.Scheme &&
		a.Hostname() == b.Hostname() &&
		a.Path == b.Path &&
		a.RawQuery == b.RawQuery &&
		a.Fragment == b.Fragment
}

// isLoopbackHost reports whether a host is the loopback interface by
// address.
//
// "localhost" is deliberately excluded. RFC 8252 section 8.3 says to use the
// literal addresses, because "localhost" goes through the resolver and can
// be pointed elsewhere by a hosts file or a DNS answer.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// ValidateRedirectURI checks whether a URI may be registered.
//
// Registration is where a bad redirect target has to be stopped: once it is
// in the client's list, exact matching will faithfully send tokens to it.
func ValidateRedirectURI(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return errorf(ErrCodeInvalidRequest, "the redirect URI is not a valid URI")
	}
	if !parsed.IsAbs() {
		return errorf(ErrCodeInvalidRequest, "the redirect URI must be absolute")
	}
	if parsed.Fragment != "" || strings.Contains(raw, "#") {
		// RFC 6749 section 3.1.2: the endpoint URI must not include a
		// fragment, and the authorization response appends its own.
		return errorf(ErrCodeInvalidRequest, "the redirect URI must not contain a fragment")
	}
	if parsed.User != nil {
		// https://app.example.com@evil.test/cb reads as app.example.com to a
		// human and resolves to evil.test.
		return errorf(ErrCodeInvalidRequest, "the redirect URI must not contain userinfo")
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return errorf(ErrCodeInvalidRequest,
			"an http redirect URI is only allowed for loopback addresses; use https")
	}

	// A private-use scheme is how a native application receives a redirect
	// without running a server, and RFC 8252 section 7.1 recommends one
	// derived from a domain the application controls — com.example.app:/cb.
	// Such a URI has no host by design.
	if isPrivateUseScheme(parsed.Scheme) {
		return nil
	}
	if parsed.Host == "" {
		return errorf(ErrCodeInvalidRequest, "the redirect URI has no host")
	}
	return nil
}

// isPrivateUseScheme reports whether a scheme is a reverse-domain name, which
// is what RFC 8252 section 7.1 asks a native application to register. The dot
// is what distinguishes one from a scheme like https or mailto; a scheme
// without one is not private-use and does need a host.
func isPrivateUseScheme(scheme string) bool {
	return scheme != "" && strings.Contains(scheme, ".")
}
