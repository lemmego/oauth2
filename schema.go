package oauth2

import (
	"github.com/lemmego/migration"
)

// SchemaStatements returns the DDL for the five tables this package owns, in
// dependency order.
//
// The dialect is a parameter rather than read from DB_DRIVER, because a
// caller here knows its target: oauth:install renders for the project's
// configured connection, and the test suite covers all three in one process,
// where a global environment variable could not be varied safely.
//
// It is exported because two callers need it: oauth:install renders it into
// migration files a project can read, edit and roll back, and the test suite
// executes it directly against each dialect. A schema that only ever appears
// inside a generated file is a schema nothing checks until a user runs it.
//
// Five tables, not Passport's six. Passport carries a separate
// oauth_personal_access_clients table only because its early versions had no
// grant-type column; here a personal access client is one whose grant_types
// contains personal_access, which removes a join and a way to be inconsistent.
//
// Several choices are made against specific failures:
//
//   - Every identifier is a VARCHAR, never the builder's UUID(). A native
//     uuid column on PostgreSQL would reject the base64url token ids and
//     whatever string an application's user ids happen to be.
//   - user_id carries no foreign key. UserProvider.GetID returns a string and
//     a project may key users on a bigint or a uuid; Passport declines the
//     same constraint. Cascading is an explicit revoke instead.
//   - No TEXT column is indexed, which MySQL rejects with error 1170.
//   - No index spans several columns, because the schema builder names a
//     multi-column index without the table prefix and index names are
//     database-global on SQLite.
//   - created_at defaults to migration.CurrentTimestamp rather than a literal
//     CURRENT_TIMESTAMP, which MySQL rejects on a DATETIME(6) with error 1067.
//   - Booleans default with a bool, not 0 or 1: PostgreSQL rejects an integer
//     default on a BOOLEAN.
func SchemaStatements(dialect, prefix string) []string {
	if prefix == "" {
		prefix = "oauth_"
	}
	if dialect == "" {
		dialect = migration.DriverSQLite
	}

	var out []string
	for _, schema := range []*migration.Schema{
		// Clients.
		//
		// secret holds hex(sha256(secret)) and is NULL for a public client.
		// confidential is stored rather than derived from secret being set,
		// so clearing a secret cannot silently turn a confidential client
		// into a public one that needs no authentication at all.
		migration.CreateFor(dialect, prefix+"clients", func(t *migration.Table) {
			t.String("id", 64).Primary()
			t.String("user_id", 64).Nullable()
			t.String("name", 255)
			t.String("secret", 64).Nullable()
			t.Text("redirect_uris")
			t.Text("grant_types")
			t.Text("scopes").Nullable()
			t.Boolean("confidential").Default(true)
			t.Boolean("first_party").Default(false)
			t.Boolean("revoked").Default(false)
			t.DateTime("created_at", 6).Default(migration.CurrentTimestamp)
			t.DateTime("updated_at", 6).Default(migration.CurrentTimestamp)
			t.Index("user_id")
		}),

		// Authorization codes.
		//
		// id is hex(sha256(code)); the code itself is never stored, so a dump
		// of this table cannot be exchanged. consumed_at is the single-use
		// latch: the exchange is an UPDATE ... WHERE consumed_at IS NULL and
		// the affected row count is the decision, so two concurrent
		// exchanges cannot both win.
		migration.CreateFor(dialect, prefix+"auth_codes", func(t *migration.Table) {
			t.String("id", 64).Primary()
			t.String("user_id", 64)
			t.String("client_id", 64)
			t.Text("scopes")
			t.Text("redirect_uri")
			t.String("code_challenge", 128).Nullable()
			t.String("code_challenge_method", 10).Nullable()
			t.String("family_id", 64)
			t.DateTime("expires_at", 6)
			t.DateTime("consumed_at", 6).Nullable()
			t.Boolean("revoked").Default(false)
			t.DateTime("created_at", 6).Default(migration.CurrentTimestamp)
			t.Index("client_id")
			t.Index("expires_at")
		}),

		// Access tokens.
		//
		// This row is the revocation. id is the JWT's jti claim and the token
		// itself is not stored: the signature already proves it was issued,
		// and this row is only ever asked whether it still counts. user_id is
		// NULL for client_credentials, where there is no resource owner.
		migration.CreateFor(dialect, prefix+"access_tokens", func(t *migration.Table) {
			t.String("id", 80).Primary()
			t.String("user_id", 64).Nullable()
			t.String("client_id", 64)
			t.String("name", 255).Nullable()
			t.Text("scopes")
			t.String("family_id", 64)
			t.Boolean("revoked").Default(false)
			t.DateTime("expires_at", 6)
			t.DateTime("created_at", 6).Default(migration.CurrentTimestamp)
			t.DateTime("updated_at", 6).Default(migration.CurrentTimestamp)
			t.Index("user_id")
			t.Index("client_id")
			t.Index("family_id")
			t.Index("expires_at")
		}),

		// Refresh tokens.
		//
		// client_id, user_id and scopes are denormalised off the access token
		// so the refresh grant is a single primary-key read, and so pruning
		// an expired access token cannot orphan a live refresh token.
		// rotated_to being set on a token being presented is the reuse signal.
		migration.CreateFor(dialect, prefix+"refresh_tokens", func(t *migration.Table) {
			t.String("id", 64).Primary()
			t.String("access_token_id", 80).Nullable()
			t.String("client_id", 64)
			t.String("user_id", 64).Nullable()
			t.Text("scopes")
			t.String("family_id", 64)
			t.String("rotated_to", 64).Nullable()
			t.Boolean("revoked").Default(false)
			t.DateTime("expires_at", 6)
			t.DateTime("created_at", 6).Default(migration.CurrentTimestamp)
			t.Index("access_token_id")
			t.Index("family_id")
			t.Index("expires_at")
		}),

		// Device codes, RFC 8628.
		//
		// Both codes are hashed. user_code_hash is unique so issuing cannot
		// mint a duplicate and leave two devices waiting on one entry; the
		// roughly 35 bits behind a user code are protected by a ten minute
		// lifetime, single use and a rate limit rather than by the hash.
		//
		// last_polled_at and interval_seconds are the slow_down machinery: a
		// poll arriving early fails a conditional UPDATE and raises the
		// interval by five seconds, as RFC 8628 section 3.5 prescribes.
		migration.CreateFor(dialect, prefix+"device_codes", func(t *migration.Table) {
			t.String("id", 64).Primary()
			t.String("user_code_hash", 64).Unique()
			t.String("client_id", 64)
			t.String("user_id", 64).Nullable()
			t.Text("scopes")
			t.String("family_id", 64)
			t.Int("interval_seconds").Default(5)
			t.Int("poll_count").Default(0)
			t.DateTime("last_polled_at", 6).Nullable()
			t.DateTime("approved_at", 6).Nullable()
			t.DateTime("denied_at", 6).Nullable()
			t.DateTime("consumed_at", 6).Nullable()
			t.DateTime("expires_at", 6)
			t.DateTime("created_at", 6).Default(migration.CurrentTimestamp)
			t.Index("client_id")
			t.Index("expires_at")
		}),
	} {
		// Statements, not Build: an index is its own statement on SQLite and
		// PostgreSQL, and MySQL's driver refuses several at once unless the
		// DSN opts in with multiStatements. A caller running this DDL itself
		// needs them apart.
		out = append(out, schema.Statements()...)
	}
	return out
}

// TableNames lists the tables this package owns, in the order a teardown
// should drop them.
func TableNames(prefix string) []string {
	if prefix == "" {
		prefix = "oauth_"
	}
	return []string{
		prefix + "device_codes",
		prefix + "refresh_tokens",
		prefix + "access_tokens",
		prefix + "auth_codes",
		prefix + "clients",
	}
}
