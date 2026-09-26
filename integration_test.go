package oauth2_test

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"github.com/lemmego/oauth2"
	"github.com/lemmego/oauth2/storetest"
	_ "github.com/lib/pq"
)

// SQLite cannot exercise PostgreSQL's $N placeholder numbering, MySQL's
// rejection of a CURRENT_TIMESTAMP default on DATETIME(6), either database's
// boolean handling, or the driver error text translateInsertErr matches on.
// These are the only tests that prove those paths, so run them after any
// change to queries.go, schema.go or the scanners.
//
//	export OAUTH2_POSTGRES_DSN="postgres://$USER@127.0.0.1:5432/lemmego_oauth2_test?sslmode=disable"
//	export OAUTH2_MYSQL_DSN="root@tcp(127.0.0.1:3306)/lemmego_oauth2_test?parseTime=true&loc=UTC"
//	go test -run TestIntegration ./...
//
// Each run drops and recreates the tables, so point them at a database you
// do not mind losing.
func TestIntegrationPostgres(t *testing.T) {
	runIntegration(t, "postgres", "postgres", "OAUTH2_POSTGRES_DSN")
}

func TestIntegrationMySQL(t *testing.T) {
	runIntegration(t, "mysql", "mysql", "OAUTH2_MYSQL_DSN")
}

func runIntegration(t *testing.T, driverName, dialect, env string) {
	dsn := os.Getenv(env)
	if dsn == "" {
		t.Skipf("%s is not set", env)
	}

	// Each subtest of the conformance suite wants an empty store, and these
	// databases are shared rather than per-test temp files, so the tables are
	// rebuilt for every one. A prefix per subtest would leave a trail behind.
	storetest.Run(t, func(t *testing.T) oauth2.Store {
		pool, err := sql.Open(driverName, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pool.Close() })

		if err := pool.Ping(); err != nil {
			t.Fatalf("connecting to %s: %v", env, err)
		}
		resetSchema(t, pool, dialect)

		store, err := oauth2.NewSQLStoreWithDB(pool, dialect)
		if err != nil {
			t.Fatal(err)
		}
		return store
	})
}

func resetSchema(t *testing.T, pool *sql.DB, dialect string) {
	t.Helper()
	for _, table := range oauth2.TableNames("oauth_") {
		if _, err := pool.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", table)); err != nil {
			t.Fatalf("dropping %s: %v", table, err)
		}
	}
	for _, statement := range oauth2.SchemaStatements(dialect, "oauth_") {
		if _, err := pool.Exec(statement); err != nil {
			t.Fatalf("schema: %v\n%s", err, statement)
		}
	}
}
