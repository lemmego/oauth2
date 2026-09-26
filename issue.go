package oauth2

import "time"

// issuePair builds the access token, and optionally the refresh token, that a
// grant hands back.
//
// The rows are built here and written by the store's transition, so a grant
// never writes a token outside the same statement that consumed whatever
// authorised it.
func (s *Server) issuePair(p issueParams) (Issued, *TokenResponse, error) {
	now := s.now()

	jti, err := randomToken(32)
	if err != nil {
		return Issued{}, nil, err
	}

	access := &AccessToken{
		ID:        jti,
		UserID:    p.UserID,
		ClientID:  p.ClientID,
		Name:      p.Name,
		Scopes:    p.Scopes,
		FamilyID:  p.FamilyID,
		ExpiresAt: now.Add(p.AccessTTL),
		CreatedAt: now,
		UpdatedAt: now,
	}

	issued := Issued{Access: access}
	response := &TokenResponse{
		TokenType: "Bearer",
		ExpiresIn: int64(p.AccessTTL / time.Second),
		Scope:     p.Scopes.String(),
	}

	if p.WithRefresh {
		refresh, err := randomToken(32)
		if err != nil {
			return Issued{}, nil, err
		}
		issued.Refresh = &RefreshToken{
			ID:            hashToken(refresh),
			AccessTokenID: jti,
			ClientID:      p.ClientID,
			UserID:        p.UserID,
			Scopes:        p.Scopes,
			FamilyID:      p.FamilyID,
			ExpiresAt:     now.Add(p.RefreshTTL),
			CreatedAt:     now,
		}
		response.RefreshToken = refresh
	}

	signed, err := s.signAccessToken(access)
	if err != nil {
		return Issued{}, nil, err
	}
	response.AccessToken = signed
	return issued, response, nil
}

type issueParams struct {
	UserID     string
	ClientID   string
	Name       string
	Scopes     Scopes
	FamilyID   string
	AccessTTL  time.Duration
	RefreshTTL time.Duration

	// WithRefresh is false for client_credentials, where RFC 6749 section
	// 4.4.3 says a refresh token should not be issued, and for personal
	// access tokens, which are not refreshed.
	WithRefresh bool
}

// TokenResponse is the body of a successful token request, RFC 6749 section
// 5.1.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// storeRefresh writes a refresh token, if the grant issued one.
func (s *Server) storeRefresh(ctx Context, token *RefreshToken) error {
	if token == nil {
		return nil
	}
	// A refresh token is only ever written alongside the access token it
	// accompanies, inside the transition that consumed whatever authorised
	// it — except here, where the authorization code's own transition has
	// already committed. Writing it separately is safe because its id is
	// freshly generated and cannot collide with anything a concurrent
	// request produced.
	if err := s.storeRefreshToken(ctx, token); err != nil {
		return errorf(ErrCodeServerError, "could not record the refresh token").WithCause(err)
	}
	return nil
}

func (s *Server) storeRefreshToken(ctx Context, token *RefreshToken) error {
	writer, ok := s.store.(RefreshWriter)
	if !ok {
		return errStoreCannotWriteRefresh
	}
	return writer.CreateRefreshToken(ctx, token)
}
