package oauth2

import (
	"net/http"
	"strings"

	"github.com/lemmego/api/app"
	"github.com/lemmego/auth"
)

// principalKey is where a verified token is put on the request context.
const principalKey = "oauth:principal"

// Protect returns middleware that requires a valid access token, and
// optionally particular scopes.
//
// It records the token's subject with auth, which then runs the application's
// own loader — so a handler written against auth.UserAs receives the same
// concrete type here as it does behind a session cookie. This package still
// has no opinion about what a user is; it hands over an id, which is a
// narrower coupling than passing an object, and auth never learns that this
// package exists.
func (p *Provider) Protect(scopes ...string) app.Handler {
	required := newScopes(scopes)

	return func(c app.Context) error {
		server := p.Server()
		if server == nil {
			return c.SetStatus(http.StatusInternalServerError).
				JSON(app.M{"error": ErrCodeServerError, "error_description": "the oauth2 server is not configured"})
		}

		token, ok := bearerToken(c.Header("Authorization"))
		if !ok {
			return unauthorized(c, "", "an access token is required")
		}

		principal, err := server.Verify(c.RequestContext(), token)
		if err != nil {
			return unauthorized(c, "invalid_token", "the access token is invalid or has expired")
		}
		if !principal.Scopes.HasAll(required) {
			// RFC 6750 section 3.1: insufficient_scope is 403, not 401 —
			// the token is valid, it simply does not grant this.
			return c.SetStatus(http.StatusForbidden).JSON(app.M{
				"error":             "insufficient_scope",
				"error_description": "this token does not grant " + required.String(),
				"scope":             required.String(),
			})
		}

		c.Set(principalKey, principal)

		if principal.UserID != "" {
			// auth loads the user from here; the handler downstream sees the
			// application's own type.
			auth.SetSubject(c, principal.UserID)
			return c.Next()
		}

		// A client-credentials token: a machine acting as itself, with no
		// user behind it. Marking it authenticated is the truth. The old
		// behaviour put the *Principal under auth's user key so that
		// AuthUser was "never nil" — which falsified the one promise auth
		// makes, and did it silently: UserAs returns false and the handler
		// renders a logged-out page.
		auth.SetAuthenticated(c)
		return c.Next()
	}
}

// PrincipalFrom returns the verified token on a request, if there is one.
func PrincipalFrom(c app.Context) (*Principal, bool) {
	principal, ok := c.Get(principalKey).(*Principal)
	return principal, ok
}

// bearerToken reads a token from an Authorization header.
//
// The scheme is parsed rather than trimmed as a literal prefix: "Bearer " is
// what a standards-compliant client sends, the comparison is
// case-insensitive per RFC 7235, and a token containing the word "bearer"
// must not be mangled.
func bearerToken(header string) (string, bool) {
	scheme, token, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return "", false
	}
	if token = strings.TrimSpace(token); token == "" {
		return "", false
	}
	return token, true
}

// unauthorized answers with the challenge RFC 6750 section 3 requires, so a
// client can tell a missing token from a rejected one.
func unauthorized(c app.Context, code, description string) error {
	challenge := `Bearer realm="api"`
	if code != "" {
		challenge += `, error="` + code + `", error_description="` + description + `"`
	}
	c.SetHeader("WWW-Authenticate", challenge)

	body := app.M{"error_description": description}
	if code != "" {
		body["error"] = code
	} else {
		body["error"] = "unauthorized"
	}
	return c.SetStatus(http.StatusUnauthorized).JSON(body)
}
