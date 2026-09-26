package oauth2

import (
	"net/http"
	"strings"

	"github.com/lemmego/api/app"
	"github.com/lemmego/auth"
)

// principalKey is where a verified token is put on the request context.
const principalKey = "oauth:principal"

// UserResolver loads the application's user for a token subject.
//
// This package cannot do it: auth.UserProvider is three getters with no
// lookup method, and oauth2 has no opinion about what a user is or which
// persistence holds it. Leave it nil and auth.AuthUser returns the
// *Principal, which is enough for scope checks and anything keyed on the id.
type UserResolver func(ctx Context, userID string) (any, error)

// Protect returns middleware that requires a valid access token, and
// optionally particular scopes.
//
// It sets both the principal and auth's own user key, so a handler already
// written against auth.AuthUser keeps working against a bearer token without
// being changed — and auth never learns that this package exists, which keeps
// the dependency pointing one way.
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

		if p.UserResolver != nil && principal.UserID != "" {
			user, err := p.UserResolver(c.RequestContext(), principal.UserID)
			if err == nil && user != nil {
				c.Set(auth.UserKey, user)
				return c.Next()
			}
		}
		// Without a resolver the principal itself stands in, so
		// auth.AuthUser is never nil for an authenticated request.
		c.Set(auth.UserKey, principal)
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
