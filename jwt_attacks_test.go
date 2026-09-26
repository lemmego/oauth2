package oauth2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// issuedToken returns a genuine token plus the harness that made it, so each
// attack below is a mutation of something that really works.
func issuedToken(t *testing.T) (*harness, string) {
	t.Helper()
	h := newHarness(t)
	client, secret := h.confidentialClient("app", GrantAuthorizationCode, GrantRefreshToken)
	code := h.authorize(client, testVerifier, "read")
	issued, err := h.exchange(client, secret, code, testVerifier)
	if err != nil {
		t.Fatal(err)
	}
	return h, issued.AccessToken
}

// claimsOf decodes a token's payload so an attack can rebuild it.
func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func assemble(t *testing.T, header, claims map[string]any, signature string) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON) + "." + signature
}

// alg:none: the attacker declares the token unsigned and supplies no
// signature. Accepting it means anyone can mint any token.
func TestAlgNoneIsRejected(t *testing.T) {
	h, token := issuedToken(t)
	claims := claimsOf(t, token)

	for _, alg := range []string{"none", "None", "NONE", "nOnE"} {
		forged := assemble(t, map[string]any{"alg": alg, "typ": "at+jwt"}, claims, "")
		if _, err := h.server.Verify(ctxOf(t), forged); err == nil {
			t.Errorf("a token with alg %q was accepted", alg)
		}
	}
}

// Algorithm confusion: sign with HMAC using the RSA public key's own bytes as
// the secret. The public key is published at the JWKS endpoint, so every
// encoding of it is attacker-known — which is exactly why the verifier must
// pin RS256 rather than trust the header.
func TestHMACConfusionIsRejected(t *testing.T) {
	h, token := issuedToken(t)
	claims := claimsOf(t, token)
	public := &sharedTestKey(t).PublicKey

	pkix, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := x509.MarshalPKCS1PublicKey(public)

	for name, secret := range map[string][]byte{
		"PKIX DER":      pkix,
		"PKCS#1 DER":    pkcs1,
		"modulus bytes": public.N.Bytes(),
		"PEM":           mustEncodePublic(t, public),
	} {
		forged := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		forged.Header["typ"] = "at+jwt"
		forged.Header["kid"] = KeyID(public)
		signed, err := forged.SignedString(secret)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := h.server.Verify(ctxOf(t), signed); err == nil {
			t.Errorf("a token signed with HS256 using the %s of the public key was accepted", name)
		}
	}
}

func mustEncodePublic(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	encoded, err := EncodePublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// Any RSA algorithm other than the one pinned must be refused, or a weaker
// one becomes available to an attacker who can influence the header.
func TestOtherAlgorithmsAreRejected(t *testing.T) {
	h, token := issuedToken(t)
	claims := claimsOf(t, token)
	key := sharedTestKey(t)

	for _, method := range []jwt.SigningMethod{
		jwt.SigningMethodRS384, jwt.SigningMethodRS512,
		jwt.SigningMethodPS256, jwt.SigningMethodPS384,
	} {
		forged := jwt.NewWithClaims(method, jwt.MapClaims(claims))
		forged.Header["typ"] = "at+jwt"
		forged.Header["kid"] = KeyID(&key.PublicKey)
		signed, err := forged.SignedString(key)
		if err != nil {
			t.Fatalf("%s: %v", method.Alg(), err)
		}
		if _, err := h.server.Verify(ctxOf(t), signed); err == nil {
			t.Errorf("a token signed with %s was accepted", method.Alg())
		}
	}
}

// A kid is a key into a map of keys already loaded. It is never a path, a
// filename or a query, so none of these can reach anything — but the test
// exists because that property is easy to lose in a refactor.
func TestKidInjectionIsRejected(t *testing.T) {
	h, token := issuedToken(t)
	claims := claimsOf(t, token)
	key := sharedTestKey(t)

	for _, kid := range []any{
		"../../etc/passwd",
		"../../../storage/oauth/private.key",
		"' OR 1=1--",
		"%00",
		strings.Repeat("A", 100000),
		"",
		nil,
		map[string]any{"jwk": "evil"},
		[]any{"a", "b"},
		42,
	} {
		forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
		forged.Header["typ"] = "at+jwt"
		if kid != nil {
			forged.Header["kid"] = kid
		} else {
			delete(forged.Header, "kid")
		}
		signed, err := forged.SignedString(key)
		if err != nil {
			t.Fatalf("%v: %v", kid, err)
		}
		if _, err := h.server.Verify(ctxOf(t), signed); err == nil {
			t.Errorf("a token with kid %#v was accepted", kid)
		}
	}
}

// RFC 9068's typ header is what stops any other JWT the application signs
// from being replayed here as an access token.
func TestTypeConfusionIsRejected(t *testing.T) {
	h, token := issuedToken(t)
	claims := claimsOf(t, token)
	key := sharedTestKey(t)

	for _, typ := range []string{"JWT", "jwt", "id_token", "at+JWTX", ""} {
		forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
		forged.Header["kid"] = KeyID(&key.PublicKey)
		if typ == "" {
			delete(forged.Header, "typ")
		} else {
			forged.Header["typ"] = typ
		}
		signed, err := forged.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.server.Verify(ctxOf(t), signed); err == nil {
			t.Errorf("a token with typ %q was accepted as an access token", typ)
		}
	}

	// And the correct one still works, so the check is not simply refusing
	// everything.
	if _, err := h.server.Verify(ctxOf(t), token); err != nil {
		t.Errorf("a genuine token was rejected: %v", err)
	}
}

// A token minted for another issuer or audience must not be accepted here,
// which is what stops one deployment's tokens working against another.
func TestCrossIssuerAndAudienceAreRejected(t *testing.T) {
	h, token := issuedToken(t)
	key := sharedTestKey(t)

	for name, mutate := range map[string]func(map[string]any){
		"another issuer":   func(c map[string]any) { c["iss"] = "https://evil.example.com" },
		"another audience": func(c map[string]any) { c["aud"] = "https://other.example.com" },
		"no issuer":        func(c map[string]any) { delete(c, "iss") },
		"no expiry":        func(c map[string]any) { delete(c, "exp") },
	} {
		claims := claimsOf(t, token)
		mutate(claims)

		forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
		forged.Header["typ"] = "at+jwt"
		forged.Header["kid"] = KeyID(&key.PublicKey)
		signed, err := forged.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.server.Verify(ctxOf(t), signed); err == nil {
			t.Errorf("a token with %s was accepted", name)
		}
	}
}

// A validly signed token whose jti names no row must fail closed: it was
// pruned, or the id was forged, and neither is a reason to admit the request.
func TestForgedJTIFailsClosed(t *testing.T) {
	h, token := issuedToken(t)
	claims := claimsOf(t, token)
	claims["jti"] = "a-jti-that-was-never-issued"
	key := sharedTestKey(t)

	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	forged.Header["typ"] = "at+jwt"
	forged.Header["kid"] = KeyID(&key.PublicKey)
	signed, err := forged.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.server.Verify(ctxOf(t), signed); err == nil {
		t.Fatal("a token whose jti names no row was accepted")
	}
}

// A token signed by a key the server does not hold must be refused even
// though it is otherwise well formed — the check that a rotated-out or
// foreign key cannot be substituted.
func TestUnknownSigningKeyIsRejected(t *testing.T) {
	h, token := issuedToken(t)
	claims := claimsOf(t, token)

	foreign, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	forged.Header["typ"] = "at+jwt"
	forged.Header["kid"] = KeyID(&foreign.PublicKey)
	signed, err := forged.SignedString(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.server.Verify(ctxOf(t), signed); err == nil {
		t.Fatal("a token signed by a key the server does not hold was accepted")
	}
}

// Tampering with the payload must break the signature. Trivially true for a
// correct implementation, and the canary for one that stops checking.
func TestTamperedPayloadIsRejected(t *testing.T) {
	h, token := issuedToken(t)
	claims := claimsOf(t, token)
	claims["scope"] = "read write admin"

	parts := strings.Split(token, ".")
	tampered := parts[0] + "." +
		base64.RawURLEncoding.EncodeToString(mustJSON(t, claims)) + "." + parts[2]

	if _, err := h.server.Verify(ctxOf(t), tampered); err == nil {
		t.Fatal("a token with a rewritten scope claim was accepted")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// The JWKS is served publicly, so anything private appearing in it would be
// a catastrophic leak.
func TestJWKSCarriesNoPrivateMaterial(t *testing.T) {
	h := newHarness(t)
	encoded, err := h.server.Keyring().MarshalJWKS()
	if err != nil {
		t.Fatal(err)
	}

	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	keys, _ := document["keys"].([]any)
	if len(keys) == 0 {
		t.Fatal("the JWKS is empty")
	}
	for _, raw := range keys {
		key, _ := raw.(map[string]any)
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, present := key[private]; present {
				t.Errorf("the JWKS exposes the private member %q", private)
			}
		}
		if key["kty"] != "RSA" || key["alg"] != "RS256" || key["use"] != "sig" {
			t.Errorf("unexpected JWK: %v", key)
		}
	}
}

// The thumbprint is checked against RFC 7638 section 3.1's worked example, so
// it is verified against the specification rather than against itself. The
// kid is what ties a token to a key across rotation, so a wrong derivation
// would make every rotated token unverifiable.
func TestKeyIDMatchesRFC7638(t *testing.T) {
	const modulus = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	raw, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		t.Fatal(err)
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(raw), E: 65537}

	if got := KeyID(key); got != want {
		t.Errorf("KeyID = %q, want the thumbprint from RFC 7638 section 3.1: %q", got, want)
	}
}
