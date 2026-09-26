package oauth2

import (
	"sort"
	"strings"
)

// Scopes is a canonical scope set: sorted and deduplicated, so two tokens
// granting the same access carry a byte-identical scope claim and can be
// compared and cached without normalising first.
type Scopes []string

// Wildcard grants every registered scope. Passport lets any client ask for
// it; here only a first-party client may, because a third-party application
// that can request everything makes the consent screen a lie.
const Wildcard = "*"

// ParseScopes reads the space-delimited form RFC 6749 section 3.3 defines.
// Repeated and empty entries are dropped rather than rejected: a client that
// sends "read  read" has asked for read.
func ParseScopes(raw string) Scopes {
	return newScopes(strings.Fields(raw))
}

func newScopes(values []string) Scopes {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make(Scopes, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// String renders the space-delimited form used in the scope parameter and the
// scope claim.
func (s Scopes) String() string { return strings.Join(s, " ") }

// Has reports whether s grants scope. A set holding the wildcard grants
// everything.
func (s Scopes) Has(scope string) bool {
	for _, held := range s {
		if held == Wildcard || held == scope {
			return true
		}
	}
	return false
}

// HasAll reports whether s grants every scope in want.
func (s Scopes) HasAll(want Scopes) bool {
	for _, scope := range want {
		if !s.Has(scope) {
			return false
		}
	}
	return true
}

// HasAny reports whether s grants at least one scope in want. An empty want
// is satisfied by anything, since it asks for nothing.
func (s Scopes) HasAny(want Scopes) bool {
	if len(want) == 0 {
		return true
	}
	for _, scope := range want {
		if s.Has(scope) {
			return true
		}
	}
	return false
}

// Subset reports whether every scope in s is granted by of.
//
// This is the check that keeps a refresh from widening a grant: the scopes
// asked for must already be held, never merely overlap them.
func (s Scopes) Subset(of Scopes) bool { return of.HasAll(s) }

// Equal reports whether two sets grant exactly the same scopes. Both are
// canonical, so this is a straight comparison.
func (s Scopes) Equal(other Scopes) bool {
	if len(s) != len(other) {
		return false
	}
	for i := range s {
		if s[i] != other[i] {
			return false
		}
	}
	return true
}
