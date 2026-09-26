package oauth2

import "errors"

// The error codes RFC 6749 section 5.2, RFC 8628 section 3.5 and RFC 7636
// define. They are the "error" member of a token-endpoint response and the
// error query parameter of a failed authorization redirect.
const (
	ErrCodeInvalidRequest          = "invalid_request"
	ErrCodeInvalidClient           = "invalid_client"
	ErrCodeInvalidGrant            = "invalid_grant"
	ErrCodeUnauthorizedClient      = "unauthorized_client"
	ErrCodeUnsupportedGrantType    = "unsupported_grant_type"
	ErrCodeUnsupportedResponseType = "unsupported_response_type"
	ErrCodeInvalidScope            = "invalid_scope"
	ErrCodeAccessDenied            = "access_denied"
	ErrCodeServerError             = "server_error"
	ErrCodeTemporarilyUnavailable  = "temporarily_unavailable"

	// Device flow, RFC 8628 section 3.5.
	ErrCodeAuthorizationPending = "authorization_pending"
	ErrCodeSlowDown             = "slow_down"
	ErrCodeExpiredToken         = "expired_token"
)

// Error is a protocol error, shaped the way RFC 6749 section 5.2 requires.
//
// The framework's own error helpers render {"message": ...}, which is the
// wrong shape here: a client library parses the "error" member and branches
// on its value, so a differently-shaped body reads as an unknown failure.
type Error struct {
	Code        string
	Description string
	URI         string

	// Status is the HTTP status to send. Zero means the default for Code.
	Status int

	// cause is kept for the server's own logs and never reaches the client:
	// the description is written for an integrator, not derived from an
	// internal failure that might name a table or a column.
	cause error
}

func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

func (e *Error) Unwrap() error { return e.cause }

// WithCause attaches an internal error for logging. It never changes what the
// client is told.
func (e *Error) WithCause(err error) *Error {
	e.cause = err
	return e
}

func errorf(code, description string) *Error {
	return &Error{Code: code, Description: description}
}

// The store's sentinels. They are deliberately distinct from the protocol
// errors above: a grant decides what a client is told, and the difference
// between "this code never existed" and "this code was already used" changes
// what the server does even though the client is told the same thing.
var (
	// ErrNotFound means no such row.
	ErrNotFound = errors.New("oauth2: not found")

	// ErrCodeReplayed means an authorization code that had already been
	// consumed was presented again. RFC 6749 section 4.1.2 requires denying
	// the request and recommends revoking everything issued from that code,
	// because a replay means the code leaked.
	ErrCodeReplayed = errors.New("oauth2: authorization code was already used")

	// ErrRefreshReused means a refresh token that had already been rotated
	// or revoked was presented again — the RFC 6819 section 5.2.2.3 signal
	// that either the client or an attacker is holding a stale token, and
	// the server cannot tell which.
	ErrRefreshReused = errors.New("oauth2: refresh token was already used")

	// ErrExpired means the row existed and its lifetime had passed.
	ErrExpired = errors.New("oauth2: expired")
)

// Further store sentinels.
var (
	// ErrDuplicate means an id that must be unique was already taken. It is
	// a bug for a generated id and a collision for a user code, which the
	// caller retries.
	ErrDuplicate = errors.New("oauth2: already exists")

	// ErrAlreadyDecided means the user has already approved or denied this
	// device authorization, so a second decision must not overwrite it.
	ErrAlreadyDecided = errors.New("oauth2: already approved or denied")

	// ErrNotApproved means a device code was exchanged before the user
	// approved it.
	ErrNotApproved = errors.New("oauth2: not approved")
)

// Token verification sentinels.
var (
	// ErrInvalidToken is what every verification failure reports.
	//
	// It is deliberately one error. Telling a caller whether a token was
	// forged, expired, revoked or signed by an unknown key is an oracle, and
	// nothing legitimate needs the distinction: the server's own logs carry
	// the detail.
	ErrInvalidToken = errors.New("oauth2: invalid token")

	errUnknownKey = errors.New("oauth2: unknown signing key")
)

// errStoreCannotWriteRefresh reports a store that does not implement
// RefreshWriter, which the authorization code grant needs.
var errStoreCannotWriteRefresh = errors.New(
	"oauth2: this store cannot write a refresh token outside a rotation")
