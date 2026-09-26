package oauth2

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// rebind walks the statement looking for "?" and is deliberately naive about
// quoting: a "?" inside a string literal would be renumbered as a parameter
// and silently corrupt the query. No statement here contains a literal, and
// that is checked rather than assumed.
func TestNoQueryContainsAStringLiteral(t *testing.T) {
	q := buildQueries("sqlite", "oauth_")
	for i, query := range q.fields() {
		if strings.ContainsAny(*query, "'\"") {
			t.Errorf("query %d contains a quote, which rebind cannot handle safely:\n%s", i, *query)
		}
	}
}

// The table prefix is interpolated, because a table name cannot be bound as a
// parameter. Anything that is not an identifier must therefore be refused.
func TestTablePrefixIsValidated(t *testing.T) {
	for _, prefix := range []string{
		"oauth_", "x", "", "a1_",
	} {
		if prefix != "" && !validTablePrefix(prefix) {
			t.Errorf("validTablePrefix(%q) = false, want true", prefix)
		}
	}
	for _, prefix := range []string{
		"oauth-", "oauth ", "o'auth", `o"auth`, "oauth;", "oauth--", "a.b",
		strings.Repeat("x", 33),
	} {
		if validTablePrefix(prefix) {
			t.Errorf("validTablePrefix(%q) = true, want false", prefix)
		}
	}
}

// PostgreSQL numbers its parameters, and a mismatch between the numbering and
// the argument order would silently compare the wrong columns rather than
// fail. So every statement is checked for a contiguous $1..$n run.
func TestPostgresPlaceholdersAreNumberedInOrder(t *testing.T) {
	sqlite := buildQueries("sqlite", "oauth_")
	postgres := buildQueries("postgres", "oauth_")

	numbered := regexp.MustCompile(`\$(\d+)`)
	sqliteFields, postgresFields := sqlite.fields(), postgres.fields()

	for i := range sqliteFields {
		wantCount := strings.Count(*sqliteFields[i], "?")
		matches := numbered.FindAllStringSubmatch(*postgresFields[i], -1)

		if len(matches) != wantCount {
			t.Errorf("query %d has %d placeholders but %d were numbered:\n%s",
				i, wantCount, len(matches), *postgresFields[i])
			continue
		}
		for n, match := range matches {
			got, err := strconv.Atoi(match[1])
			if err != nil {
				t.Fatal(err)
			}
			if got != n+1 {
				t.Errorf("query %d numbers its %d%s placeholder $%d:\n%s",
					i, n+1, ordinal(n+1), got, *postgresFields[i])
				break
			}
		}
		if strings.Contains(*postgresFields[i], "?") {
			t.Errorf("query %d still contains an unnumbered placeholder:\n%s", i, *postgresFields[i])
		}
	}
}

func ordinal(n int) string {
	switch {
	case n%100 >= 11 && n%100 <= 13:
		return "th"
	case n%10 == 1:
		return "st"
	case n%10 == 2:
		return "nd"
	case n%10 == 3:
		return "rd"
	default:
		return "th"
	}
}

// PostgreSQL rejects an integer where a BOOLEAN belongs, so the 0 and 1 the
// statements are written with have to become FALSE and TRUE — but only where
// they are boolean comparisons, never where they are arithmetic.
func TestBooleanLiteralsAreRewrittenForPostgresOnly(t *testing.T) {
	q := buildQueries("postgres", "oauth_")
	for i, query := range q.fields() {
		if strings.Contains(*query, "revoked = 0") || strings.Contains(*query, "revoked = 1") {
			t.Errorf("query %d compares a boolean against an integer on postgres:\n%s", i, *query)
		}
	}
	// Arithmetic must survive untouched, or the device poll stops counting.
	if !strings.Contains(q.penaliseDevicePoll, "interval_seconds + 5") {
		t.Errorf("the slow_down increment was rewritten:\n%s", q.penaliseDevicePoll)
	}
	if !strings.Contains(q.penaliseDevicePoll, "poll_count + 1") {
		t.Errorf("the poll counter was rewritten:\n%s", q.penaliseDevicePoll)
	}

	// And the other dialects must keep the integers they accept.
	sqlite := buildQueries("sqlite", "oauth_")
	if !strings.Contains(sqlite.revokeAccessByFamily, "revoked = 0") {
		t.Errorf("sqlite lost its integer boolean:\n%s", sqlite.revokeAccessByFamily)
	}
}

// The prefix reaches every table name, or a project that set one would find
// half its tables under the default.
func TestTablePrefixReachesEveryStatement(t *testing.T) {
	q := buildQueries("sqlite", "custom_")
	for i, query := range q.fields() {
		if strings.Contains(*query, "oauth_") {
			t.Errorf("query %d ignores the configured table prefix:\n%s", i, *query)
		}
		if !strings.Contains(*query, "custom_") {
			t.Errorf("query %d names no prefixed table:\n%s", i, *query)
		}
	}
}
