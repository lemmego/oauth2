package oauth2

import (
	"net/url"
	"strings"
)

// RedirectError is a failure the client learns about through its own redirect
// URI, as RFC 6749 section 4.1.2.1 requires.
//
// It exists as a distinct type because the decision of whether to redirect an
// error or render it is the difference between an authorization server and an
// open redirector: anything discovered before redirect_uri is validated must
// be rendered, and everything after it is redirected. Making that a type
// rather than a boolean means a handler cannot forget which it is holding.
type RedirectError struct {
	RedirectURI string
	State       string
	Err         *Error
}

func (e *RedirectError) Error() string { return e.Err.Error() }

func (e *RedirectError) Unwrap() error { return e.Err }

// Location is the URL to send the user agent to.
//
// The error is appended to whatever query the registered URI already carried,
// rather than replacing it, because a client may legitimately register a
// redirect with parameters of its own.
func (e *RedirectError) Location() string {
	return appendQuery(e.RedirectURI, func(values url.Values) {
		values.Set("error", e.Err.Code)
		if e.Err.Description != "" {
			values.Set("error_description", e.Err.Description)
		}
		if e.Err.URI != "" {
			values.Set("error_uri", e.Err.URI)
		}
		if e.State != "" {
			values.Set("state", e.State)
		}
	})
}

// SuccessRedirect is where to send the user agent after an approved
// authorization.
func SuccessRedirect(redirectURI, code, state string) string {
	return appendQuery(redirectURI, func(values url.Values) {
		values.Set("code", code)
		if state != "" {
			values.Set("state", state)
		}
	})
}

// appendQuery adds parameters to a URI, preserving what it already had.
//
// It falls back to string concatenation for a URI that will not parse, which
// only happens for a private-use scheme some parsers handle oddly; the
// registered set has already been validated, so this is never handling
// arbitrary input.
func appendQuery(raw string, set func(url.Values)) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		values := url.Values{}
		set(values)
		separator := "?"
		if strings.Contains(raw, "?") {
			separator = "&"
		}
		return raw + separator + values.Encode()
	}

	values := parsed.Query()
	set(values)
	parsed.RawQuery = values.Encode()
	return parsed.String()
}
