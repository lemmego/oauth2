package oauth2

import (
	"errors"
	"net/url"
)

// AuthorizeRequest is a parsed and validated /authorize request.
type AuthorizeRequest struct {
	Client              *Client
	RedirectURI         string
	State               string
	Scopes              Scopes
	CodeChallenge       string
	CodeChallengeMethod string
}

// ParseAuthorizeRequest validates an authorization request.
//
// The order matters and is the difference between an authorization server and
// an open redirector. Anything wrong with client_id or redirect_uri is
// returned as a plain error, for the caller to render: RFC 6749 section
// 4.1.2.1 says the server must NOT redirect when it cannot trust where it
// would be redirecting to. Everything after that is a RedirectError, carrying
// the error back to the client the way the specification wants.
func (s *Server) ParseAuthorizeRequest(ctx Context, params url.Values) (*AuthorizeRequest, error) {
	clientID := params.Get("client_id")
	if clientID == "" {
		return nil, errorf(ErrCodeInvalidRequest, "client_id is required")
	}

	client, err := s.store.Client(ctx, clientID)
	if errors.Is(err, ErrNotFound) {
		return nil, errorf(ErrCodeInvalidClient, "unknown client")
	}
	if err != nil {
		return nil, errorf(ErrCodeServerError, "could not read the client").WithCause(err)
	}
	if client.Revoked {
		return nil, errorf(ErrCodeInvalidClient, "this client has been revoked")
	}
	if !client.AllowsGrant(GrantAuthorizationCode) {
		return nil, errorf(ErrCodeUnauthorizedClient,
			"this client is not registered for the authorization code grant")
	}

	redirectURI := params.Get("redirect_uri")
	switch {
	case redirectURI == "" && len(client.RedirectURIs) == 1:
		// Omitting it is only unambiguous when exactly one is registered.
		redirectURI = client.RedirectURIs[0]
	case redirectURI == "":
		return nil, errorf(ErrCodeInvalidRequest,
			"redirect_uri is required because this client registered more than one")
	case !matchRedirectURI(client.RedirectURIs, redirectURI):
		return nil, errorf(ErrCodeInvalidRequest, "redirect_uri does not match a registered URI")
	}

	// From here the redirect target is trusted, so failures travel back to
	// the client rather than being rendered.
	state := params.Get("state")
	redirect := func(err *Error) error {
		return &RedirectError{RedirectURI: redirectURI, State: state, Err: err}
	}

	if responseType := params.Get("response_type"); responseType != "code" {
		// Implicit is not implemented rather than disabled, so there is no
		// configuration that could turn it back on.
		return nil, redirect(errorf(ErrCodeUnsupportedResponseType,
			"only the code response_type is supported"))
	}

	scopes, err := s.validateScopes(client, ParseScopes(params.Get("scope")))
	if err != nil {
		var protocolErr *Error
		if errors.As(err, &protocolErr) {
			return nil, redirect(protocolErr)
		}
		return nil, redirect(errorf(ErrCodeInvalidScope, err.Error()))
	}

	challenge := params.Get("code_challenge")
	method := params.Get("code_challenge_method")
	if challenge == "" {
		if s.cfg.RequirePKCE || client.IsPublic() {
			return nil, redirect(errorf(ErrCodeInvalidRequest,
				"code_challenge is required; this server requires PKCE"))
		}
	} else if err := validateChallengeMethod(method); err != nil {
		var protocolErr *Error
		if errors.As(err, &protocolErr) {
			return nil, redirect(protocolErr)
		}
		return nil, redirect(errorf(ErrCodeInvalidRequest, err.Error()))
	}

	return &AuthorizeRequest{
		Client:              client,
		RedirectURI:         redirectURI,
		State:               state,
		Scopes:              scopes,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
	}, nil
}

// GrantAuthorization issues an authorization code for an approved request.
//
// The scopes come from the request the user was shown, not from anything the
// caller passes separately, so what is granted is what was displayed — unless
// the user narrowed them, which approved carries.
func (s *Server) GrantAuthorization(ctx Context, request *AuthorizeRequest, userID string, approved Scopes) (string, error) {
	if userID == "" {
		return "", errorf(ErrCodeServerError, "no resource owner was identified")
	}
	if len(approved) == 0 {
		approved = request.Scopes
	}
	// A user may narrow what was asked for; they may never widen it.
	if !approved.Subset(request.Scopes) {
		return "", errorf(ErrCodeInvalidScope, "the approved scopes exceed what was requested")
	}

	code, err := randomToken(32)
	if err != nil {
		return "", err
	}
	family, err := newFamilyID()
	if err != nil {
		return "", err
	}

	now := s.now()
	if err := s.store.CreateAuthCode(ctx, &AuthCode{
		ID:                  hashToken(code),
		UserID:              userID,
		ClientID:            request.Client.ID,
		Scopes:              approved,
		RedirectURI:         request.RedirectURI,
		CodeChallenge:       request.CodeChallenge,
		CodeChallengeMethod: request.CodeChallengeMethod,
		FamilyID:            family,
		ExpiresAt:           now.Add(s.cfg.AuthCodeTTL),
		CreatedAt:           now,
	}); err != nil {
		return "", errorf(ErrCodeServerError, "could not record the authorization").WithCause(err)
	}
	return code, nil
}

// DenyAuthorization builds the redirect for a user who refused.
func (s *Server) DenyAuthorization(request *AuthorizeRequest) *RedirectError {
	return &RedirectError{
		RedirectURI: request.RedirectURI,
		State:       request.State,
		Err:         errorf(ErrCodeAccessDenied, "the user refused the request"),
	}
}

// ExchangeAuthorizationCode redeems a code for tokens.
func (s *Server) ExchangeAuthorizationCode(ctx Context, client *Client, params url.Values) (*TokenResponse, error) {
	if !client.AllowsGrant(GrantAuthorizationCode) {
		return nil, errorf(ErrCodeUnauthorizedClient,
			"this client is not registered for the authorization code grant")
	}

	presented := params.Get("code")
	if presented == "" {
		return nil, errorf(ErrCodeInvalidRequest, "code is required")
	}

	family, err := newFamilyID()
	if err != nil {
		return nil, err
	}

	// The code is consumed before the client, redirect and PKCE checks, so a
	// failed check still burns it. An attacker holding a stolen code but not
	// the verifier gets one attempt, not an unlimited number.
	issued, response, err := s.issuePair(issueParams{
		ClientID:    client.ID,
		FamilyID:    family,
		AccessTTL:   s.cfg.AccessTokenTTL,
		RefreshTTL:  s.cfg.RefreshTokenTTL,
		WithRefresh: true,
		Scopes:      nil, // filled in below, once the code is known
	})
	if err != nil {
		return nil, errorf(ErrCodeServerError, "could not issue a token").WithCause(err)
	}

	code, err := s.store.ExchangeAuthCode(ctx, hashToken(presented), Issued{}, s.now())
	switch {
	case errors.Is(err, ErrCodeReplayed):
		// RFC 6749 section 4.1.2 requires denying the request and
		// recommends revoking everything issued from the code, because a
		// replay means it leaked.
		if code != nil {
			_ = s.store.RevokeFamily(ctx, code.FamilyID, s.now())
		}
		return nil, errorf(ErrCodeInvalidGrant, "this authorization code has already been used")
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrExpired):
		return nil, errorf(ErrCodeInvalidGrant, "the authorization code is invalid or has expired")
	case err != nil:
		return nil, errorf(ErrCodeServerError, "could not read the authorization code").WithCause(err)
	}

	// Bound client. Without this, client B can redeem a code issued to
	// client A — the code substitution attack.
	if !constantTimeEqual(code.ClientID, client.ID) {
		_ = s.store.RevokeFamily(ctx, code.FamilyID, s.now())
		return nil, errorf(ErrCodeInvalidGrant, "this code was issued to a different client")
	}
	// Bound redirect. The URI at exchange time must be the one bound to the
	// code, or a code stolen via one redirect can be redeemed through another.
	if presentedURI := params.Get("redirect_uri"); presentedURI != code.RedirectURI {
		return nil, errorf(ErrCodeInvalidGrant, "redirect_uri does not match the authorization")
	}
	if err := verifyPKCE(code.CodeChallenge, code.CodeChallengeMethod, params.Get("code_verifier")); err != nil {
		return nil, err
	}

	// The code carried the granted scopes, so the token cannot widen them
	// however the request was shaped.
	issued.Access.Scopes = code.Scopes
	issued.Access.UserID = code.UserID
	issued.Access.FamilyID = code.FamilyID
	issued.Refresh.Scopes = code.Scopes
	issued.Refresh.UserID = code.UserID
	issued.Refresh.FamilyID = code.FamilyID
	response.Scope = code.Scopes.String()

	signed, err := s.signAccessToken(issued.Access)
	if err != nil {
		return nil, errorf(ErrCodeServerError, "could not sign the token").WithCause(err)
	}
	response.AccessToken = signed

	if err := s.store.CreateAccessToken(ctx, issued.Access); err != nil {
		return nil, errorf(ErrCodeServerError, "could not record the token").WithCause(err)
	}
	if err := s.storeRefresh(ctx, issued.Refresh); err != nil {
		return nil, err
	}
	return response, nil
}
