package oauth2

import (
	"errors"
	"net/url"
)

// RefreshTokens exchanges a refresh token for a new pair.
//
// Rotation is the default: the presented token is spent and a new one issued.
// Presenting a spent token revokes the entire family — including the
// successor the honest client is holding. That is the correct outcome and not
// an over-reaction: one of the two holders is an attacker, the server cannot
// tell which, so both are made to authenticate again. RFC 6819 section
// 5.2.2.3.
func (s *Server) RefreshTokens(ctx Context, client *Client, params url.Values) (*TokenResponse, error) {
	if !client.AllowsGrant(GrantRefreshToken) {
		return nil, errorf(ErrCodeUnauthorizedClient,
			"this client is not registered for the refresh token grant")
	}

	presented := params.Get("refresh_token")
	if presented == "" {
		return nil, errorf(ErrCodeInvalidRequest, "refresh_token is required")
	}
	presentedID := hashToken(presented)

	stored, err := s.store.RefreshToken(ctx, presentedID)
	if errors.Is(err, ErrNotFound) {
		return nil, errInvalidRefresh
	}
	if err != nil {
		return nil, errorf(ErrCodeServerError, "could not read the refresh token").WithCause(err)
	}

	// Bound client, checked before anything else is done with the token: a
	// refresh token issued to one client must not be usable by another even
	// if that other client is otherwise legitimate.
	if !constantTimeEqual(stored.ClientID, client.ID) {
		_ = s.store.RevokeFamily(ctx, stored.FamilyID, s.now())
		return nil, errInvalidRefresh
	}

	scopes := stored.Scopes
	if requested := ParseScopes(params.Get("scope")); len(requested) > 0 {
		// RFC 6749 section 6: the scope of a refreshed token may be narrowed
		// but never widened, and never beyond what the original grant held.
		if !requested.Subset(stored.Scopes) {
			return nil, errorf(ErrCodeInvalidScope,
				"a refreshed token cannot be granted scopes the original was not")
		}
		scopes = requested
	}

	issued, response, err := s.issuePair(issueParams{
		UserID:      stored.UserID,
		ClientID:    client.ID,
		Scopes:      scopes,
		FamilyID:    stored.FamilyID,
		AccessTTL:   s.cfg.AccessTokenTTL,
		RefreshTTL:  s.cfg.RefreshTokenTTL,
		WithRefresh: s.cfg.RefreshRotation,
	})
	if err != nil {
		return nil, errorf(ErrCodeServerError, "could not issue a token").WithCause(err)
	}

	// Without rotation the presented token stays valid and only a new access
	// token is issued. That is weaker and is not the default, but a
	// deployment with clients that cannot store a new token may need it.
	if !s.cfg.RefreshRotation {
		if err := s.store.CreateAccessToken(ctx, issued.Access); err != nil {
			return nil, errorf(ErrCodeServerError, "could not record the token").WithCause(err)
		}
		response.RefreshToken = presented
		return response, nil
	}

	_, err = s.store.RotateRefresh(ctx, presentedID, issued, s.now())
	switch {
	case errors.Is(err, ErrRefreshReused):
		if err := s.store.RevokeFamily(ctx, stored.FamilyID, s.now()); err != nil {
			return nil, errorf(ErrCodeServerError, "could not revoke the token family").WithCause(err)
		}
		return nil, errorf(ErrCodeInvalidGrant,
			"this refresh token has already been used; every token from the same authorization has been revoked")
	case errors.Is(err, ErrExpired):
		return nil, errInvalidRefresh
	case errors.Is(err, ErrNotFound):
		return nil, errInvalidRefresh
	case err != nil:
		return nil, errorf(ErrCodeServerError, "could not rotate the refresh token").WithCause(err)
	}
	return response, nil
}

// errInvalidRefresh is one message for every way a refresh token can be
// unusable. Telling a client whether a token was unknown, expired or bound to
// another client is an oracle, and nothing legitimate needs the distinction.
var errInvalidRefresh = errorf(ErrCodeInvalidGrant, "the refresh token is invalid or has expired")
