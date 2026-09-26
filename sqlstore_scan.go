package oauth2

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// rebind converts the "?" placeholders every query in this package is written
// with into the numbered form PostgreSQL requires.
//
// This is the whole of the dialect layer. Nothing here needs RETURNING,
// because every primary key is generated in Go; nothing needs an upsert,
// because issuing a duplicate id is a bug the unique constraint should
// surface; nothing calls NOW(), because time is a bound parameter from an
// injectable clock; and no column or table name in this schema is reserved in
// any of the three dialects, so nothing needs quoting.
//
// It is deliberately naive about string literals. No query in this package
// contains one, and TestNoQueryContainsAStringLiteral asserts that, so the
// naivety is checked rather than assumed.
func rebind(dialect, query string) string {
	if dialect != "postgres" {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] != '?' {
			b.WriteByte(query[i])
			continue
		}
		n++
		b.WriteByte('$')
		b.WriteString(strconv.Itoa(n))
	}
	return b.String()
}

// timeValue reads a timestamp column whatever shape the driver chose for it.
//
// SQLite returns a DATETIME(6) column as text, because its driver only maps a
// declared type of exactly "datetime" to time.Time and "datetime(6)" falls
// through. MySQL returns time.Time only when the DSN carries parseTime=true,
// which the ORM connector sets but a caller who opened the pool themselves
// may not. Accepting all three beats failing on a perfectly ordinary schema.
//
// This is the same problem, and the same answer, as orm.timeScanner.
type timeValue struct{ into *time.Time }

var timeLayouts = []string{
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

func (v timeValue) Scan(src any) error {
	switch value := src.(type) {
	case nil:
		*v.into = time.Time{}
	case time.Time:
		*v.into = value.UTC()
	case string:
		return v.parse(value)
	case []byte:
		return v.parse(string(value))
	default:
		return fmt.Errorf("oauth2: cannot read %T as a timestamp", src)
	}
	return nil
}

func (v timeValue) parse(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		*v.into = time.Time{}
		return nil
	}
	for _, layout := range timeLayouts {
		// A stored timestamp carries no zone, and every write is UTC, so
		// parsing in UTC is what makes the round trip an identity.
		if parsed, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			*v.into = parsed.UTC()
			return nil
		}
	}
	return fmt.Errorf("oauth2: cannot parse %q as a timestamp", raw)
}

// nullTimeValue reads a nullable timestamp into a *time.Time, leaving it nil
// when the column is NULL. The nil is meaningful in this schema: it is what
// "not yet consumed", "not yet approved" and "never polled" mean.
type nullTimeValue struct{ into **time.Time }

func (v nullTimeValue) Scan(src any) error {
	if src == nil {
		*v.into = nil
		return nil
	}
	var parsed time.Time
	if err := (timeValue{into: &parsed}).Scan(src); err != nil {
		return err
	}
	if parsed.IsZero() {
		*v.into = nil
		return nil
	}
	*v.into = &parsed
	return nil
}

// utc normalises a value on the way in. Every timestamp this package writes
// goes through here, so a server running in a non-UTC zone cannot shift an
// expiry by its offset.
func utc(t time.Time) time.Time { return t.UTC() }

func utcPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

// Lists are stored as JSON text rather than a delimited string, so a value
// containing the delimiter cannot split one entry into two. A redirect URI is
// the value that matters here: splitting one would create a redirect target
// nobody registered.

func encodeList(values []string) string {
	if values == nil {
		values = []string{}
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		// Marshalling []string cannot fail; treat it as empty rather than
		// panicking inside a request.
		return "[]"
	}
	return string(encoded)
}

func decodeList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	return values
}

func encodeScopes(s Scopes) string { return encodeList([]string(s)) }

func decodeScopes(raw string) Scopes { return newScopes(decodeList(raw)) }

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func stringFrom(v sql.NullString) string {
	if !v.Valid {
		return ""
	}
	return v.String
}
