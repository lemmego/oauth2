package oauth2

import "net/url"

// ClientCredentialsGrant issues a token that stands for the application
// itself, with no resource owner involved.
//
// No refresh token is issued: RFC 6749 section 4.4.3 says so, and the reason
// is that the client can always ask for another token with the credentials it
// already holds, so a refresh token would be a second credential with no
// additional capability and one more thing to leak.
func (s *Server) ClientCredentialsGrant(ctx Context, client *Client, params url.Values) (*TokenResponse, error) {
	if !client.AllowsGrant(GrantClientCredentials) {
		return nil, errorf(ErrCodeUnauthorizedClient,
			"this client is not registered for the client credentials grant")
	}
	// A public client's "credential" is its id, which is not a secret, so
	// there is nothing for this grant to authenticate.
	if client.IsPublic() {
		return nil, errorf(ErrCodeUnauthorizedClient,
			"the client credentials grant requires a confidential client")
	}

	scopes, err := s.validateScopes(client, ParseScopes(params.Get("scope")))
	if err != nil {
		return nil, err
	}

	family, err := newFamilyID()
	if err != nil {
		return nil, err
	}

	issued, response, err := s.issuePair(issueParams{
		ClientID:  client.ID,
		Scopes:    scopes,
		FamilyID:  family,
		AccessTTL: s.cfg.AccessTokenTTL,
	})
	if err != nil {
		return nil, errorf(ErrCodeServerError, "could not issue a token").WithCause(err)
	}
	if err := s.store.CreateAccessToken(ctx, issued.Access); err != nil {
		return nil, errorf(ErrCodeServerError, "could not record the token").WithCause(err)
	}
	return response, nil
}

// CreatePersonalAccessToken issues a long-lived token a user made for
// themselves, the way a repository host issues an API token.
//
// It is not an HTTP grant: there is no client to authenticate and no redirect
// to follow, so it is called from the application's own settings page. The
// name is stored on the row so the user can recognise it later and revoke the
// right one.
func (s *Server) CreatePersonalAccessToken(ctx Context, userID, name string, scopes Scopes) (*TokenResponse, *AccessToken, error) {
	if userID == "" {
		return nil, nil, errorf(ErrCodeInvalidRequest, "a personal access token needs a user")
	}

	client, err := s.personalAccessClient(ctx)
	if err != nil {
		return nil, nil, err
	}

	granted, err := s.validateScopes(client, scopes)
	if err != nil {
		return nil, nil, err
	}

	family, err := newFamilyID()
	if err != nil {
		return nil, nil, err
	}

	issued, response, err := s.issuePair(issueParams{
		UserID:    userID,
		ClientID:  client.ID,
		Name:      name,
		Scopes:    granted,
		FamilyID:  family,
		AccessTTL: s.cfg.PersonalTokenTTL,
	})
	if err != nil {
		return nil, nil, errorf(ErrCodeServerError, "could not issue a token").WithCause(err)
	}
	if err := s.store.CreateAccessToken(ctx, issued.Access); err != nil {
		return nil, nil, errorf(ErrCodeServerError, "could not record the token").WithCause(err)
	}
	return response, issued.Access, nil
}

// PersonalAccessClientID is the well-known id of the client personal access
// tokens are issued against.
//
// Passport keeps a whole table to record which client this is. A fixed id
// does the same job: there is one such client, it is created by
// oauth:install, and a lookup by primary key needs no extra table.
const PersonalAccessClientID = "personal-access-client"

func (s *Server) personalAccessClient(ctx Context) (*Client, error) {
	client, err := s.store.Client(ctx, PersonalAccessClientID)
	if err != nil {
		return nil, errorf(ErrCodeServerError,
			"no personal access client exists; run `lemmego run oauth:client --personal`").WithCause(err)
	}
	if client.Revoked || !client.AllowsGrant(GrantPersonalAccess) {
		return nil, errorf(ErrCodeServerError,
			"the personal access client is revoked or not registered for the grant")
	}
	return client, nil
}
