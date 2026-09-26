package oauth2

import "time"

// Grant types this server implements. Implicit and password are absent by
// choice, not by configuration: implicit is obsolete, and the password grant
// is deprecated by RFC 9700 because it requires the client to handle the
// user's credentials directly. Passport dropped both as well.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"

	// GrantPersonalAccess is not an HTTP grant. It marks the client that
	// personal access tokens are issued against, which is why Passport needs
	// a separate oauth_personal_access_clients table and this does not.
	GrantPersonalAccess = "personal_access"
)

// Client is a registered application.
type Client struct {
	ID     string
	UserID string // owner; empty for a machine client
	Name   string

	// SecretHash is hex(sha256(secret)), empty for a public client.
	//
	// A client secret is 32 bytes from crypto/rand, so there is no
	// dictionary to defend against and nothing for a slow hash to buy. The
	// application's user passwords are a different problem and still use
	// bcrypt; see checkSecret for why the two differ.
	SecretHash string

	RedirectURIs []string
	GrantTypes   []string

	// Scopes limits what this client may ever request. Empty means any
	// registered scope.
	Scopes Scopes

	// Confidential is stored rather than derived from SecretHash being set,
	// so clearing a secret cannot silently turn a confidential client into a
	// public one that needs no authentication at all.
	Confidential bool

	// FirstParty marks a client the application itself owns. Consent can be
	// skipped for one, and only one may request the wildcard scope.
	FirstParty bool

	Revoked   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AllowsGrant reports whether the client is registered for a grant type.
func (c *Client) AllowsGrant(grant string) bool {
	for _, allowed := range c.GrantTypes {
		if allowed == grant {
			return true
		}
	}
	return false
}

// IsPublic reports whether the client authenticates with only its id. A
// public client must use PKCE, since its "credential" is not a secret.
func (c *Client) IsPublic() bool { return !c.Confidential }

// AuthCode is an issued authorization code. ID is hex(sha256(code)); the code
// itself is never stored, so a dump of this table cannot be exchanged.
type AuthCode struct {
	ID                  string
	UserID              string
	ClientID            string
	Scopes              Scopes
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	FamilyID            string
	ExpiresAt           time.Time
	ConsumedAt          *time.Time
	Revoked             bool
	CreatedAt           time.Time
}

// AccessToken is the row that makes revocation real. ID is the JWT's jti
// claim; the token itself is not stored, because the signature already proves
// it was issued and this row is only asked whether it still counts.
type AccessToken struct {
	ID       string
	UserID   string // empty for client_credentials: there is no resource owner
	ClientID string
	Name     string // a personal access token's label, shown to its owner
	Scopes   Scopes
	FamilyID string
	Revoked  bool

	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RefreshToken is a rotating credential. ID is hex(sha256(token)).
//
// ClientID, UserID and Scopes are denormalised off the access token so that
// the refresh grant is a single primary-key read, and so pruning an expired
// access token cannot orphan a refresh token that is still live.
type RefreshToken struct {
	ID            string
	AccessTokenID string
	ClientID      string
	UserID        string
	Scopes        Scopes
	FamilyID      string

	// RotatedTo names the token issued in exchange for this one. A non-empty
	// value on a token being presented is the reuse signal: this credential
	// was already spent, so one of its two holders is an attacker.
	RotatedTo string

	Revoked   bool
	ExpiresAt time.Time
	CreatedAt time.Time
}

// DeviceCode is an in-progress device authorization, RFC 8628. Both codes are
// hashed: ID is hex(sha256(device_code)) and UserCodeHash is the same over the
// normalised user code.
type DeviceCode struct {
	ID           string
	UserCodeHash string
	ClientID     string
	UserID       string // set when the user approves
	Scopes       Scopes // requested, narrowed on approval
	FamilyID     string

	// IntervalSeconds is the minimum gap between polls. It grows by five
	// seconds each time a device polls early, which is what slow_down means.
	IntervalSeconds int
	PollCount       int
	LastPolledAt    *time.Time

	ApprovedAt *time.Time
	DeniedAt   *time.Time
	ConsumedAt *time.Time
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// Issued is the pair a grant produces. Refresh is nil for client_credentials
// and for personal access tokens, neither of which may be refreshed.
type Issued struct {
	Access  *AccessToken
	Refresh *RefreshToken
}

// PollOutcome is what a device poll resolved to.
type PollOutcome int

const (
	PollPending PollOutcome = iota
	PollSlowDown
	PollDenied
	PollExpired
	PollReady
)

// PruneResult counts what housekeeping removed, per table, so the command can
// say what it did.
type PruneResult struct {
	AuthCodes     int64
	AccessTokens  int64
	RefreshTokens int64
	DeviceCodes   int64
}
