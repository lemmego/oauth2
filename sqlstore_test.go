package oauth2_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/glebarez/go-sqlite"
	"github.com/lemmego/oauth2"
	"github.com/lemmego/oauth2/storetest"
)

// newSQLiteStore builds a store over a fresh file-backed SQLite database.
//
// A file rather than :memory: because the conformance suite runs concurrent
// transitions, and each pooled connection to an in-memory SQLite gets its own
// empty database — the concurrency checks would then pass for the wrong
// reason.
func newSQLiteStore(t *testing.T) oauth2.Store {
	t.Helper()

	pool, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "oauth2.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })

	// SQLite serialises writers, and the conformance suite deliberately
	// contends. Without a busy timeout the losers fail with SQLITE_BUSY
	// instead of waiting, which would look like the single-use latch working
	// when it is really the database refusing to answer.
	if _, err := pool.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		t.Fatal(err)
	}

	for _, statement := range oauth2.SchemaStatements("sqlite", "oauth_") {
		if _, err := pool.Exec(statement); err != nil {
			t.Fatalf("schema: %v\n%s", err, statement)
		}
	}

	store, err := oauth2.NewSQLStoreWithDB(pool, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestSQLStoreSatisfiesTheContract(t *testing.T) {
	storetest.Run(t, newSQLiteStore)
}
