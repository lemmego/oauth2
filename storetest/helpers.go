package storetest

import (
	"strconv"

	"github.com/lemmego/oauth2"
)

func itoa(i int) string { return strconv.Itoa(i) }

// second discards a typed first return so a table can hold just the errors.
func second[T any](_ T, err error) error { return err }

// seedRefresh writes a refresh token without going through a rotation.
//
// The Store deliberately has no CreateRefreshToken: a refresh token is only
// ever produced by issuing one, so exposing a bare create would be an API for
// putting the store into a state the protocol cannot reach. Tests need that
// state, and reach it the way the protocol does — by issuing.
func seedRefresh(s oauth2.Store, token *oauth2.RefreshToken) error {
	code := authCode("seed-"+token.ID, token.FamilyID)
	if err := s.CreateAuthCode(ctx(), code); err != nil {
		return err
	}
	// Only the refresh token: a caller that also wants the access token row
	// creates it itself, and issuing one here would collide with it.
	_, err := s.ExchangeAuthCode(ctx(), code.ID, oauth2.Issued{Refresh: token}, base)
	return err
}
