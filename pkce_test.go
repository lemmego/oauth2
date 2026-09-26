package oauth2

import (
	"strings"
	"testing"
)

const goodVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func TestPKCEAcceptsAMatchingVerifier(t *testing.T) {
	if err := verifyPKCE(ChallengeFor(goodVerifier), "S256", goodVerifier); err != nil {
		t.Fatalf("a matching verifier was rejected: %v", err)
	}
	// RFC 7636 appendix B's worked example, so the derivation is checked
	// against the specification rather than against itself.
	if got := ChallengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("ChallengeFor = %q, want the value from RFC 7636 appendix B", got)
	}
}

// The classic implementation bug: comparing the presented verifier against
// the stored challenge instead of deriving. That accepts the challenge itself
// as a verifier, so anyone who saw the authorization request can redeem the
// code and PKCE protects nothing.
func TestPKCERejectsTheChallengePresentedAsAVerifier(t *testing.T) {
	challenge := ChallengeFor(goodVerifier)
	if err := verifyPKCE(challenge, "S256", challenge); err == nil {
		t.Fatal("the challenge was accepted as its own verifier")
	}
}

// Dropping code_verifier must not turn PKCE off.
func TestPKCERejectsAStrippedVerifier(t *testing.T) {
	if err := verifyPKCE(ChallengeFor(goodVerifier), "S256", ""); err == nil {
		t.Fatal("a missing verifier was accepted for a code bound to a challenge")
	}
}

// RFC 7636 makes plain the default when the method is omitted, so an absent
// method is a downgrade rather than an oversight.
func TestPKCERejectsPlainAndAnOmittedMethod(t *testing.T) {
	for _, method := range []string{"plain", "", "PLAIN", "s1", "none"} {
		if err := validateChallengeMethod(method); err == nil {
			t.Errorf("validateChallengeMethod(%q) accepted a method that is not S256", method)
		}
	}
	if err := validateChallengeMethod("S256"); err != nil {
		t.Errorf("S256 was rejected: %v", err)
	}
	if err := validateChallengeMethod("s256"); err != nil {
		t.Errorf("a lowercase s256 was rejected: %v", err)
	}
}

// A code with no challenge and a verifier presented anyway is a confused or
// malicious client, not a harmless extra.
func TestPKCERejectsAVerifierForANonPKCEAuthorization(t *testing.T) {
	if err := verifyPKCE("", "", "some-verifier"); err == nil {
		t.Fatal("a verifier was accepted for an authorization that used no PKCE")
	}
	if err := verifyPKCE("", "", ""); err != nil {
		t.Fatalf("a non-PKCE authorization with no verifier was rejected: %v", err)
	}
}

func TestVerifierShapeIsEnforced(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verifier string
	}{
		{"one character below the floor", strings.Repeat("a", 42)},
		{"one character above the ceiling", strings.Repeat("a", 129)},
		{"empty", ""},
		{"contains +", strings.Repeat("a", 42) + "+"},
		{"contains /", strings.Repeat("a", 42) + "/"},
		{"contains =", strings.Repeat("a", 42) + "="},
		{"contains a space", strings.Repeat("a", 42) + " "},
	} {
		if err := ValidateVerifier(tc.verifier); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	for _, verifier := range []string{
		strings.Repeat("a", 43),
		strings.Repeat("a", 128),
		"abc-._~" + strings.Repeat("Z", 36),
	} {
		if err := ValidateVerifier(verifier); err != nil {
			t.Errorf("a valid verifier was rejected: %v", err)
		}
	}
}
