package oauth2_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lemmego/api/app"
	"github.com/lemmego/oauth2"
)

// The published migration has to compile in the project it lands in, run
// against a real database, and — the reason it is published at all — still
// work after someone edits it.
//
// This builds a throwaway module around the stub and runs it, rather than
// asserting on the text, because "it parses" would not have caught a call
// that does not exist or DDL the database refuses.
func TestPublishedMigrationRunsAndCanBeEdited(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles a module and runs a migration")
	}
	requireGo(t)

	root := t.TempDir()
	provider := &oauth2.Provider{}

	// Publish the way `lemmego publish --tags=migrations` does.
	var migrationPath string
	for _, publishable := range provider.AddPublishables() {
		if publishable.Tag != oauth2.TagMigrations {
			continue
		}
		migrationPath = filepath.Join(root, "migrations", filepath.Base(publishable.FilePath))
		local := &app.Publishable{
			FilePath: migrationPath,
			Content:  publishable.Content,
			Tag:      publishable.Tag,
		}
		wrote, err := local.Publish()
		if err != nil {
			t.Fatal(err)
		}
		if !wrote {
			t.Fatal("the migration was not published")
		}
	}
	if migrationPath == "" {
		t.Fatal("no migration is offered for publishing")
	}

	writeHarness(t, root)
	tidy(t, root)

	// As published.
	tables := runHarness(t, root, "as published")
	for _, want := range []string{
		"oauth_clients", "oauth_auth_codes", "oauth_access_tokens",
		"oauth_refresh_tokens", "oauth_device_codes",
	} {
		if !strings.Contains(tables, want) {
			t.Errorf("%s was not created:\n%s", want, tables)
		}
	}

	// Now edit it, which is the whole point of publishing. Two edits a real
	// project would plausibly make: add a column, and drop a table it does
	// not need.
	source, err := os.ReadFile(migrationPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(source),
		`t.Boolean("first_party").Default(false)`,
		`t.Boolean("first_party").Default(false)
		t.String("owner_team", 64).Nullable()`, 1)
	if edited == string(source) {
		t.Fatal("the edit did not apply; the stub's shape changed")
	}

	start := strings.Index(edited, `if _, err := tx.Exec(migration.Create("oauth_device_codes"`)
	if start < 0 {
		t.Fatal("could not find the device code table to remove")
	}
	end := strings.Index(edited[start:], "\n\t}\n")
	if end < 0 {
		t.Fatal("could not find the end of the device code table")
	}
	edited = edited[:start] + edited[start+end+len("\n\t}\n"):]

	if err := os.WriteFile(migrationPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}

	tables = runHarness(t, root, "after editing")
	if !strings.Contains(tables, "owner_team") {
		t.Errorf("the added column did not reach the database:\n%s", tables)
	}
	if strings.Contains(tables, "oauth_device_codes") {
		t.Errorf("the removed table was created anyway:\n%s", tables)
	}
	if !strings.Contains(tables, "oauth_clients") {
		t.Errorf("editing the migration broke the rest of it:\n%s", tables)
	}
}

func requireGo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH")
	}
}

// writeHarness builds a module around the published migration that runs it
// and prints the resulting schema.
//
// It requires only the migration package, deliberately. A stub that reached
// back into oauth2 for its schema would fail to compile here, so this is also
// what keeps the published file self-contained and therefore editable.
func writeHarness(t *testing.T, root string) {
	t.Helper()

	repo, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}

	write(t, filepath.Join(root, "go.mod"), `module stubcheck

go 1.27

require (
	github.com/glebarez/go-sqlite v1.22.0
	github.com/lemmego/migration v0.1.20
)

replace github.com/lemmego/migration => `+filepath.Join(repo, "migration")+`
`)

	write(t, filepath.Join(root, "main.go"), `package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/glebarez/go-sqlite"
	"github.com/lemmego/migration"

	_ "stubcheck/migrations"
)

func main() {
	db, err := sql.Open("sqlite", os.Args[1])
	if err != nil {
		panic(err)
	}
	defer db.Close()

	migrator, err := migration.Init(db, migration.DriverSQLite)
	if err != nil {
		panic(err)
	}
	if err := migrator.Up(-1); err != nil {
		panic(err)
	}

	rows, err := db.Query("SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name")
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var ddl sql.NullString
		if err := rows.Scan(&name, &ddl); err != nil {
			panic(err)
		}
		fmt.Println(name, ddl.String)
	}
}
`)
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// tidy resolves the harness module's dependencies once, so the two runs only
// compile.
func tidy(t *testing.T, root string) {
	t.Helper()
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("resolving the harness module: %v\n%s", err, output)
	}
}

func runHarness(t *testing.T, root, stage string) string {
	t.Helper()

	database := filepath.Join(t.TempDir(), "check.sqlite")
	cmd := exec.Command("go", "run", ".", database)
	cmd.Dir = root
	// GOWORK=off so the throwaway module resolves through its own replace
	// rather than being swallowed by the workspace.
	cmd.Env = append(os.Environ(), "GOWORK=off", "DB_DRIVER=sqlite")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: running the published migration failed: %v\n%s", stage, err, output)
	}
	return string(output)
}
