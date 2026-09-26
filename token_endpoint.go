package oauth2

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

// Token handles a token request, whichever grant it names.
//
// The caller supplies the Authorization header and the parsed POST body.
// Reading the body rather than the merged form is the caller's job and it
// matters: net/http's ParseForm merges the URL query into r.Form, so a server
// reading that would accept client credentials in a query string, where they
// end up in access logs and browser history.
func (s *Server) Token(ctx Context, authorization string, body url.Values) (*TokenResponse, error) {
	grantType := body.Get("grant_type")
	if grantType == "" {
		return nil, errorf(ErrCodeInvalidRequest, "grant_type is required")
	}

	client, err := s.AuthenticateClient(ctx, authorization, body)
	if err != nil {
		return nil, err
	}

	// Rate limited per client: the endpoint is cheap to call and the work it
	// does — an RSA signature and several queries — is not.
	if allowed, retryAfter := s.limiter.Allow(ctx, "token:"+client.ID, 60, time.Minute); !allowed {
		return nil, &Error{
			Code:        ErrCodeTemporarilyUnavailable,
			Description: "too many token requests; slow down",
			Status:      429,
			cause:       errors.New("rate limited for " + retryAfter.String()),
		}
	}

	switch grantType {
	case GrantAuthorizationCode:
		return s.ExchangeAuthorizationCode(ctx, client, body)
	case GrantRefreshToken:
		return s.RefreshTokens(ctx, client, body)
	case GrantClientCredentials:
		return s.ClientCredentialsGrant(ctx, client, body)
	case GrantDeviceCode:
		return s.ExchangeDeviceCode(ctx, client, body)
	case "password", "implicit":
		// Named explicitly so the answer is "this server does not do that"
		// rather than "unknown grant". The password grant is deprecated by
		// RFC 9700 and implicit is obsolete; Passport dropped both.
		return nil, errorf(ErrCodeUnsupportedGrantType,
			"the "+grantType+" grant is not supported; use the authorization code grant with PKCE")
	default:
		return nil, errorf(ErrCodeUnsupportedGrantType, "unsupported grant_type")
	}
}

// Revoke handles RFC 7009 token revocation.
//
// The response is success whatever happened, including for a token that never
// existed. RFC 7009 section 2.2 requires that: a client cannot be expected to
// know whether its token was already invalid, and distinguishing the cases
// would let anyone probe which tokens exist.
func (s *Server) Revoke(ctx Context, authorization string, body url.Values) error {
	client, err := s.AuthenticateClient(ctx, authorization, body)
	if err != nil {
		return err
	}

	presented := body.Get("token")
	if presented == "" {
		return errorf(ErrCodeInvalidRequest, "token is required")
	}

	hint := body.Get("token_type_hint")
	now := s.now()

	// The hint is only a hint, so both kinds are tried; it just decides
	// which to try first.
	order := []string{"access_token", "refresh_token"}
	if hint == "refresh_token" {
		order = []string{"refresh_token", "access_token"}
	}

	for _, kind := range order {
		if kind == "refresh_token" {
			stored, err := s.store.RefreshToken(ctx, hashToken(presented))
			if err == nil && constantTimeEqual(stored.ClientID, client.ID) {
				// Revoking a refresh token takes its access token with it:
				// they are one grant, and leaving the access token live
				// would make revocation mean less than a caller expects.
				return s.store.RevokeFamily(ctx, stored.FamilyID, now)
			}
			continue
		}

		if principal, err := s.Verify(ctx, presented); err == nil {
			if !constantTimeEqual(principal.ClientID, client.ID) {
				// Another client's token. Report success without doing
				// anything, per the same reasoning as above.
				return nil
			}
			return s.store.RevokeAccessToken(ctx, principal.TokenID, now)
		}
	}
	return nil
}

// IntrospectionResponse is RFC 7662 section 2.2.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	JTI       string `json:"jti,omitempty"`
}

// Introspect handles RFC 7662 token introspection.
//
// An inactive token returns exactly {"active": false} and nothing else. RFC
// 7662 section 2.2 is explicit about that: any additional field would tell a
// caller something about a token it could not otherwise verify.
func (s *Server) Introspect(ctx Context, authorization string, body url.Values) (*IntrospectionResponse, error) {
	client, err := s.AuthenticateClient(ctx, authorization, body)
	if err != nil {
		return nil, err
	}
	// RFC 7662 section 2.1: the endpoint must not be open to public clients,
	// which could otherwise use it to probe tokens they were not issued.
	if client.IsPublic() {
		return nil, errorf(ErrCodeInvalidClient,
			"introspection requires a confidential client")
	}

	presented := body.Get("token")
	if presented == "" {
		return nil, errorf(ErrCodeInvalidRequest, "token is required")
	}

	principal, err := s.Verify(ctx, presented)
	if err != nil {
		return &IntrospectionResponse{Active: false}, nil
	}

	return &IntrospectionResponse{
		Active:    true,
		Scope:     principal.Scopes.String(),
		ClientID:  principal.ClientID,
		TokenType: "Bearer",
		Exp:       principal.ExpiresAt.Unix(),
		Sub:       principal.UserID,
		Aud:       s.cfg.Audience,
		Iss:       s.cfg.Issuer,
		JTI:       principal.TokenID,
	}, nil
}

// Metadata is the authorization server metadata document, RFC 8414.
type Metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ServiceDocumentation              string   `json:"service_documentation,omitempty"`
}

// Metadata builds the discovery document.
//
// Advertising only S256 under code_challenge_methods_supported is how a
// correct client learns not to attempt plain, rather than discovering it with
// a rejected request.
func (s *Server) Metadata() *Metadata {
	scopes := make([]string, 0, len(s.cfg.Scopes))
	for scope := range s.cfg.Scopes {
		scopes = append(scopes, scope)
	}
	sortStrings(scopes)

	return &Metadata{
		Issuer:                      strings.TrimRight(s.cfg.Issuer, "/"),
		AuthorizationEndpoint:       s.cfg.URL("/authorize"),
		TokenEndpoint:               s.cfg.URL("/token"),
		JWKSURI:                     s.cfg.RootURL("/.well-known/jwks.json"),
		DeviceAuthorizationEndpoint: s.cfg.URL("/device/code"),
		RevocationEndpoint:          s.cfg.URL("/revoke"),
		IntrospectionEndpoint:       s.cfg.URL("/introspect"),
		ScopesSupported:             scopes,
		ResponseTypesSupported:      []string{"code"},
		GrantTypesSupported: []string{
			GrantAuthorizationCode,
			GrantRefreshToken,
			GrantClientCredentials,
			GrantDeviceCode,
		},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{ChallengeMethodS256},
	}
}
