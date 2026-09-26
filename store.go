package oauth2

import (
	"context"
	"time"
)

// Store persists the protocol's state.
//
// The methods are transitions, not CRUD. Consuming an authorization code,
// rotating a refresh token and claiming a device poll each have to be atomic
// against a concurrent identical request, so each is one method whose result
// distinguishes "it worked" from "it was already used" and from "it never
// existed". Exposing Get and Update instead would let every caller
// re-implement that race, and one of them would get it wrong.
//
// Unlike cache.Cache this is an interface: none of these methods declare
// their own type parameters, so there is nothing for Go's ban on generic
// interface methods to break. That buys a fast in-memory implementation for
// the adversarial suite, which runs thousands of cases per test.
//
// Every id a caller passes is already hashed. The store never sees a usable
// credential, so a store implementation cannot leak one.
type Store interface {
	// --- clients ---

	Client(ctx context.Context, id string) (*Client, error)
	CreateClient(ctx context.Context, c *Client) error
	UpdateClient(ctx context.Context, c *Client) error
	ClientsForUser(ctx context.Context, userID string) ([]*Client, error)

	// RevokeClient revokes the client and everything issued to it, so the
	// cost of a revocation is paid once by an administrator rather than by
	// every request thereafter.
	RevokeClient(ctx context.Context, id string, now time.Time) error

	// --- authorization code grant ---

	CreateAuthCode(ctx context.Context, code *AuthCode) error

	// ExchangeAuthCode consumes the code and writes the issued pair in one
	// transaction, returning the code that was consumed.
	//
	// ErrCodeReplayed means the code existed and had already been consumed;
	// the caller must then revoke the family, because a replay means the
	// code leaked. ErrNotFound means it never existed and ErrExpired that
	// its lifetime had passed. The client is told invalid_grant for all
	// three — the distinction is for the server.
	ExchangeAuthCode(ctx context.Context, codeID string, issue Issued, now time.Time) (*AuthCode, error)

	// --- refresh grant ---

	RefreshToken(ctx context.Context, id string) (*RefreshToken, error)

	// RotateRefresh revokes the presented token, records what replaced it,
	// and writes the new pair, in one transaction.
	//
	// ErrRefreshReused means it was already revoked or already rotated. The
	// caller must then revoke the whole family, including the successor the
	// honest client is holding: one of the two holders is an attacker and
	// the server cannot tell which, so both must authenticate again.
	RotateRefresh(ctx context.Context, oldID string, issue Issued, now time.Time) (*RefreshToken, error)

	// --- tokens ---

	CreateAccessToken(ctx context.Context, t *AccessToken) error

	// AccessToken is the hot path: one indexed primary-key read on every
	// authenticated request, which is what a self-contained token costs if
	// revocation is to mean anything.
	AccessToken(ctx context.Context, jti string) (*AccessToken, error)

	AccessTokensForUser(ctx context.Context, userID string) ([]*AccessToken, error)
	RevokeAccessToken(ctx context.Context, jti string, now time.Time) error

	// RevokeFamily kills every token descended from one grant.
	RevokeFamily(ctx context.Context, familyID string, now time.Time) error

	// RevokeForUserClient is what "disconnect this application" does on a
	// user's settings page.
	RevokeForUserClient(ctx context.Context, userID, clientID string, now time.Time) error

	// --- device grant ---

	CreateDeviceCode(ctx context.Context, d *DeviceCode) error
	DeviceCodeByUserCode(ctx context.Context, userCodeHash string) (*DeviceCode, error)
	ApproveDeviceCode(ctx context.Context, userCodeHash, userID string, scopes Scopes, now time.Time) error
	DenyDeviceCode(ctx context.Context, userCodeHash string, now time.Time) error

	// PollDeviceCode enforces the polling interval atomically and reports
	// what the device should be told. A poll that arrives early raises the
	// interval by five seconds, which is what RFC 8628 section 3.5 means by
	// slow_down.
	PollDeviceCode(ctx context.Context, id string, now time.Time) (*DeviceCode, PollOutcome, error)

	// ExchangeDeviceCode consumes an approved device code and writes the
	// issued pair, with the same single-use latch as an authorization code.
	ExchangeDeviceCode(ctx context.Context, id string, issue Issued, now time.Time) (*DeviceCode, error)

	// --- housekeeping ---

	// Prune removes rows that expired before the given time.
	Prune(ctx context.Context, before time.Time) (PruneResult, error)
}
