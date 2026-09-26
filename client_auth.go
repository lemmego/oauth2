package oauth2

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
)

// zeroDigest stands in for a client that does not exist, so a lookup miss
// still performs the same comparison work as a wrong secret.
var zeroDigest = strings.Repeat("0", sha256.Size*2)

// HashSecret is how a client secret is stored.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ClientCredentials are the credentials presented on a token request.
type ClientCredentials struct {
	ID     string
	Secret string

	// FromHeader records that they arrived in an Authorization header, which
	// RFC 6749 section 2.3.1 prefers.
	FromHeader bool
}

// ParseBasicAuth reads client credentials from an Authorization header.
//
// RFC 6749 section 2.3.1 requires the id and secret to be form-urlencoded
// before being joined with a colon and base64ed. Most implementations skip
// the decode and then break on any secret containing a percent or a plus, so
// both readings are tried: the encoded one first, falling back to the raw
// bytes for a client that did not encode.
func ParseBasicAuth(header string) (ClientCredentials, bool) {
	const prefix = "basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ClientCredentials{}, false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return ClientCredentials{}, false
	}

	id, secret, found := strings.Cut(string(decoded), ":")
	if !found {
		// No colon at all is not a credential, however it is read.
		return ClientCredentials{}, false
	}

	if decodedID, err := url.QueryUnescape(id); err == nil {
		id = decodedID
	}
	if decodedSecret, err := url.QueryUnescape(secret); err == nil {
		secret = decodedSecret
	}
	if id == "" {
		return ClientCredentials{}, false
	}
	return ClientCredentials{ID: id, Secret: secret, FromHeader: true}, true
}

// AuthenticateClient resolves and verifies the client on a token request.
//
// Credentials present in both the Authorization header and the request body
// are rejected rather than resolved by preference. RFC 6749 section 2.3
// forbids using more than one authentication method at once, and that
// ambiguity is how a server ends up authenticating one client while acting
// for another.
func (s *Server) AuthenticateClient(ctx Context, header string, body url.Values) (*Client, error) {
	basic, hasBasic := ParseBasicAuth(header)
	bodyID := body.Get("client_id")
	bodySecret := body.Get("client_secret")

	if hasBasic && (bodyID != "" || bodySecret != "") {
		return nil, errorf(ErrCodeInvalidClient,
			"client credentials were sent in both the Authorization header and the request body")
	}

	credentials := basic
	if !hasBasic {
		credentials = ClientCredentials{ID: bodyID, Secret: bodySecret}
	}
	if credentials.ID == "" {
		return nil, errorf(ErrCodeInvalidClient, "no client_id was provided")
	}

	client, err := s.store.Client(ctx, credentials.ID)
	if err != nil && err != ErrNotFound {
		return nil, errorf(ErrCodeServerError, "could not read the client").WithCause(err)
	}

	// The comparison runs whether or not the client exists, so "no such
	// client" and "wrong secret" take the same path and the same time.
	authenticated := checkSecret(client, credentials.Secret)

	if client == nil || client.Revoked {
		return nil, errInvalidClient
	}
	if client.Confidential {
		if !authenticated {
			return nil, errInvalidClient
		}
		return client, nil
	}

	// A public client has no secret to prove anything with, so presenting
	// one means the caller is confused about which client it is.
	if credentials.Secret != "" {
		return nil, errorf(ErrCodeInvalidClient,
			"this client is public and must not send a client_secret")
	}
	return client, nil
}

var errInvalidClient = errorf(ErrCodeInvalidClient, "client authentication failed")

// checkSecret compares a presented secret against the stored digest in
// constant time, doing the same work for a client that does not exist.
//
// SHA-256 rather than bcrypt: a client secret is 32 bytes from crypto/rand,
// so there is no dictionary to make expensive and nothing a slow hash would
// buy — while cost-10 bcrypt would add tens of milliseconds to every request
// at an unauthenticated endpoint, which is both a throughput problem and an
// amplification vector. bcrypt stays right for a user's password, which is
// human-chosen and low entropy, and silently truncates at 72 bytes besides.
func checkSecret(client *Client, presented string) bool {
	stored := zeroDigest
	if client != nil && client.SecretHash != "" {
		stored = client.SecretHash
	}

	sum := sha256.Sum256([]byte(presented))
	got := hex.EncodeToString(sum[:])
	matched := subtle.ConstantTimeCompare([]byte(got), []byte(stored)) == 1

	return matched && client != nil && client.SecretHash != ""
}

// constantTimeEqual compares two identifiers without leaking where they
// diverge. Client ids are not secret, but comparing them in constant time
// costs nothing and keeps the habit uniform across the package.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
