package oauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The JWT profile for OAuth 2.0 access tokens, RFC 9068.
//
// Adopting it rather than inventing a claim set costs nothing and buys the
// typ header check, which is what stops a token minted by the auth package —
// or any other JWT the application happens to sign — from being replayed here
// as an access token.
const accessTokenType = "at+jwt"

// accessClaims is the claim set of an issued access token.
type accessClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

// randomToken returns a URL-safe credential with the given entropy.
//
// crypto/rand failing is not survivable here: returning a low-entropy or
// empty token would hand out a guessable credential, so the error is
// returned and every caller propagates it. utils.GenerateRandomString is
// deliberately not used — it returns "" on a rand failure, silently.
func randomToken(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("oauth2: cannot generate a token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// hashToken is how every credential is stored.
//
// SHA-256 rather than bcrypt: these are 32 bytes from crypto/rand, so there
// is no dictionary to make expensive and nothing for a slow hash to buy,
// while cost-10 bcrypt would add tens of milliseconds to every token request
// at an unauthenticated endpoint. Bcrypt remains right for a user's password,
// which is human-chosen and low entropy.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newFamilyID identifies every token descended from one grant, so revoking a
// chain is one indexed update per table.
func newFamilyID() (string, error) { return randomToken(32) }

// Principal is what a verified access token resolves to.
type Principal struct {
	TokenID   string // the jti, and the row that makes revocation real
	UserID    string // empty for client_credentials: there is no resource owner
	ClientID  string
	Scopes    Scopes
	ExpiresAt time.Time
}

// HasScope reports whether the token grants a scope.
func (p *Principal) HasScope(scope string) bool { return p.Scopes.Has(scope) }

// HasAllScopes reports whether the token grants every one of them.
func (p *Principal) HasAllScopes(scopes ...string) bool { return p.Scopes.HasAll(newScopes(scopes)) }

// HasAnyScope reports whether the token grants at least one.
func (p *Principal) HasAnyScope(scopes ...string) bool { return p.Scopes.HasAny(newScopes(scopes)) }

// IsClientCredentials reports whether the token stands for an application
// rather than a person. The token's sub claim is the client id in that case,
// which is ambiguous on its own — this reads the row instead.
func (p *Principal) IsClientCredentials() bool { return p.UserID == "" }

// signAccessToken renders and signs the JWT for an access token row.
func (s *Server) signAccessToken(token *AccessToken) (string, error) {
	ring := s.keys.Load()
	if ring == nil {
		return "", fmt.Errorf("oauth2: no signing key is loaded")
	}
	key, kid := ring.Sign()

	// RFC 9068 section 2.2: sub is the resource owner, or the client itself
	// when the grant involved no user.
	subject := token.UserID
	if subject == "" {
		subject = token.ClientID
	}

	claims := accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{s.cfg.Audience},
			ID:        token.ID,
			IssuedAt:  jwt.NewNumericDate(token.CreatedAt),
			NotBefore: jwt.NewNumericDate(token.CreatedAt),
			ExpiresAt: jwt.NewNumericDate(token.ExpiresAt),
		},
		ClientID: token.ClientID,
		Scope:    token.Scopes.String(),
	}

	signed := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed.Header["kid"] = kid
	signed.Header["typ"] = accessTokenType
	return signed.SignedString(key)
}

// Verify checks an access token and resolves it to a principal.
func (s *Server) Verify(ctx Context, raw string) (*Principal, error) {
	ring := s.keys.Load()
	if ring == nil {
		return nil, fmt.Errorf("oauth2: no signing key is loaded")
	}

	parsed, err := jwt.ParseWithClaims(strings.TrimSpace(raw), &accessClaims{},
		func(token *jwt.Token) (any, error) {
			kid, _ := token.Header["kid"].(string)
			key, ok := ring.PublicKey(kid)
			if !ok {
				// No fallback to "try every key": that would turn an unknown
				// kid into a silent success and make rotation untestable.
				return nil, errUnknownKey
			}
			return key, nil
		},
		// Pin the algorithm. Removing this line was measured: alg:none and
		// HS256 confusion still fail, because the key function returns an
		// *rsa.PublicKey and the library will not hand that to an HMAC
		// verifier. What it does let through is substitution within the RSA
		// family — RS384, RS512, PS256 — so this is what keeps the accepted
		// algorithm the one actually intended, and the HMAC case is defence
		// in depth from the library rather than from here.
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(s.cfg.Issuer),
		jwt.WithAudience(s.cfg.Audience),
		jwt.WithExpirationRequired(),
		// Without this the library validates exp and nbf against the wall
		// clock while everything else here uses the injected one, so the two
		// halves of verification could disagree — and an expiry test could
		// only be written by sleeping.
		jwt.WithTimeFunc(s.now),
	)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Without the typ check, any RS256 token this key ever signed — an id
	// token, something an unrelated part of the application minted — would
	// be accepted here as an access token.
	if typ, _ := parsed.Header["typ"].(string); !strings.EqualFold(typ, accessTokenType) {
		return nil, ErrInvalidToken
	}

	claims, ok := parsed.Claims.(*accessClaims)
	if !ok || claims.ID == "" {
		return nil, ErrInvalidToken
	}

	if s.cfg.Revocation == RevocationNever {
		return &Principal{
			TokenID:   claims.ID,
			UserID:    subjectUser(claims),
			ClientID:  claims.ClientID,
			Scopes:    ParseScopes(claims.Scope),
			ExpiresAt: claims.ExpiresAt.Time,
		}, nil
	}

	// One indexed primary-key read. The signature proves the token was
	// issued; this row proves it still counts.
	row, err := s.store.AccessToken(ctx, claims.ID)
	if err != nil {
		// A missing row fails closed. It means the token was pruned or the
		// jti was forged, and neither is a reason to admit the request.
		return nil, ErrInvalidToken
	}
	if row.Revoked || !row.ExpiresAt.After(s.now()) {
		return nil, ErrInvalidToken
	}

	return &Principal{
		TokenID:   row.ID,
		UserID:    row.UserID,
		ClientID:  row.ClientID,
		Scopes:    row.Scopes,
		ExpiresAt: row.ExpiresAt,
	}, nil
}

// subjectUser reads the user from the claims when the revocation row is not
// consulted. sub is the client id for a client_credentials token, so it can
// only be read as a user when it differs from client_id.
func subjectUser(claims *accessClaims) string {
	if claims.Subject == claims.ClientID {
		return ""
	}
	return claims.Subject
}
