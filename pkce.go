package oauth2

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// The only challenge method this server accepts.
//
// RFC 7636 also defines "plain", where the challenge is the verifier. That
// protects against nothing an attacker who can read the authorization
// response cannot already defeat, and RFC 9700 says to reject it. Note also
// that RFC 7636 makes "plain" the default when the method is omitted, so an
// absent method has to be rejected too rather than treated as unset.
const ChallengeMethodS256 = "S256"

// verifierMinLength and verifierMaxLength are RFC 7636 section 4.1.
const (
	verifierMinLength = 43
	verifierMaxLength = 128
)

// validVerifierChars is the unreserved set RFC 7636 allows.
func validVerifierChar(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '-', r == '.', r == '_', r == '~':
		return true
	}
	return false
}

// ValidateVerifier checks the shape of a code verifier.
//
// The length floor is what makes the verifier unguessable; without it a
// client could send a one-character verifier and PKCE would prove nothing.
func ValidateVerifier(verifier string) error {
	if len(verifier) < verifierMinLength || len(verifier) > verifierMaxLength {
		return errorf(ErrCodeInvalidGrant, "the code verifier must be between 43 and 128 characters")
	}
	for _, r := range verifier {
		if !validVerifierChar(r) {
			return errorf(ErrCodeInvalidGrant, "the code verifier contains a character RFC 7636 does not allow")
		}
	}
	return nil
}

// ChallengeFor derives the S256 challenge for a verifier: the base64url,
// unpadded, SHA-256 of the verifier's ASCII bytes.
func ChallengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyPKCE checks a verifier against the challenge bound to a code.
//
// The comparison is constant time, and it derives the challenge rather than
// comparing the verifier to the stored value — the classic implementation
// bug is to compare them directly, which accepts the challenge itself as a
// verifier and makes PKCE a no-op for anyone who saw the authorization
// request.
func verifyPKCE(challenge, method, verifier string) error {
	if challenge == "" {
		// No challenge was bound to this code. A verifier presented anyway
		// means a confused or malicious client, not a harmless extra.
		if verifier != "" {
			return errorf(ErrCodeInvalidRequest, "a code_verifier was sent for an authorization that used no PKCE")
		}
		return nil
	}
	if verifier == "" {
		return errorf(ErrCodeInvalidGrant, "this authorization used PKCE, so a code_verifier is required")
	}
	if !strings.EqualFold(method, ChallengeMethodS256) {
		return errorf(ErrCodeInvalidGrant, "only the S256 challenge method is supported")
	}
	if err := ValidateVerifier(verifier); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(ChallengeFor(verifier)), []byte(challenge)) != 1 {
		return errorf(ErrCodeInvalidGrant, "the code_verifier does not match the code_challenge")
	}
	return nil
}

// validateChallengeMethod checks what an authorization request asked for.
func validateChallengeMethod(method string) error {
	// An omitted method means "plain" under RFC 7636, so it cannot be
	// silently accepted as "unset".
	if method == "" {
		return errorf(ErrCodeInvalidRequest,
			"code_challenge_method is required and must be S256; an omitted method means plain, which is not accepted")
	}
	if !strings.EqualFold(method, ChallengeMethodS256) {
		return errorf(ErrCodeInvalidRequest, "only the S256 code_challenge_method is supported")
	}
	return nil
}
