package oauth2

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// The published migration spells its schema out so a project can edit it,
// which means it can also fall behind SchemaStatements — the definition this
// package's own store and tests are written against.
//
// Once a project publishes the file the two are meant to diverge; that is the
// point of publishing. What must not happen is shipping a stub that already
// disagreed before anyone touched it, so the drift is pinned here.
func TestPublishedMigrationMatchesTheSchema(t *testing.T) {
	fromStub := tableDefinitions(t, MigrationStub, "stub")

	source, err := os.ReadFile("schema.go")
	if err != nil {
		t.Fatal(err)
	}
	fromSchema := tableDefinitions(t, string(source), "schema.go")

	for name, want := range fromSchema {
		got, ok := fromStub[name]
		if !ok {
			t.Errorf("the published migration does not create %s", name)
			continue
		}
		if len(got) != len(want) {
			t.Errorf("%s: the migration declares %d columns and indexes, the schema %d\nmigration: %v\nschema:    %v",
				name, len(got), len(want), got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s line %d:\n  migration: %s\n  schema:    %s", name, i+1, got[i], want[i])
			}
		}
	}
	for name := range fromStub {
		if _, ok := fromSchema[name]; !ok {
			t.Errorf("the published migration creates %s, which the schema does not", name)
		}
	}
	if len(fromSchema) == 0 {
		t.Fatal("no tables were found in schema.go; this test is not checking anything")
	}
}

// tableDefinitions parses Go source and returns, per table, the builder calls
// that define it — t.String("id", 64).Primary() and so on — rendered back to
// text so two spellings of the same schema compare equal.
func tableDefinitions(t *testing.T, source, label string) map[string][]string {
	t.Helper()

	// The stub is a file; schema.go is too. Both parse as one.
	file, err := parser.ParseFile(token.NewFileSet(), label+".go", source, parser.AllErrors)
	if err != nil {
		t.Fatalf("parsing %s: %v", label, err)
	}

	tables := map[string][]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name, body, ok := tableCall(call)
		if !ok {
			return true
		}
		tables[name] = builderCalls(body)
		return true
	})
	return tables
}

// tableCall recognises migration.Create("name", func(t *migration.Table){...})
// and migration.CreateFor(dialect, prefix+"name", ...), returning the table
// name with any prefix expression reduced to its literal part.
func tableCall(call *ast.CallExpr) (string, *ast.FuncLit, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", nil, false
	}
	if selector.Sel.Name != "Create" && selector.Sel.Name != "CreateFor" {
		return "", nil, false
	}
	if len(call.Args) < 2 {
		return "", nil, false
	}

	body, ok := call.Args[len(call.Args)-1].(*ast.FuncLit)
	if !ok {
		return "", nil, false
	}
	name, ok := tableName(call.Args[len(call.Args)-2])
	if !ok {
		return "", nil, false
	}
	return name, body, true
}

// tableName reads "oauth_clients" from either a plain literal or from
// prefix+"clients", normalising both onto the same value so a stub written
// with the default prefix compares against a schema written with a variable.
func tableName(expr ast.Expr) (string, bool) {
	switch node := expr.(type) {
	case *ast.BasicLit:
		if node.Kind != token.STRING {
			return "", false
		}
		return strings.Trim(node.Value, `"`), true
	case *ast.BinaryExpr:
		if node.Op != token.ADD {
			return "", false
		}
		right, ok := node.Y.(*ast.BasicLit)
		if !ok || right.Kind != token.STRING {
			return "", false
		}
		// The schema builds the name as prefix+"clients"; the stub writes
		// the default prefix out. Compare on the default.
		return "oauth_" + strings.Trim(right.Value, `"`), true
	}
	return "", false
}

// builderCalls renders each t.Xxx(...) chain in a table body back to text.
func builderCalls(body *ast.FuncLit) []string {
	var calls []string
	for _, statement := range body.Body.List {
		expr, ok := statement.(*ast.ExprStmt)
		if !ok {
			continue
		}
		calls = append(calls, renderExpr(expr.X))
	}
	return calls
}

func renderExpr(expr ast.Expr) string {
	switch node := expr.(type) {
	case *ast.CallExpr:
		args := make([]string, 0, len(node.Args))
		for _, arg := range node.Args {
			args = append(args, renderExpr(arg))
		}
		return renderExpr(node.Fun) + "(" + strings.Join(args, ", ") + ")"
	case *ast.SelectorExpr:
		return renderExpr(node.X) + "." + node.Sel.Name
	case *ast.Ident:
		return node.Name
	case *ast.BasicLit:
		return node.Value
	case *ast.BinaryExpr:
		return renderExpr(node.X) + node.Op.String() + renderExpr(node.Y)
	}
	return "?"
}

// The published file has to compile in the project it lands in, and a stub
// that does not parse is only discovered by whoever publishes it.
func TestStubsParse(t *testing.T) {
	for name, source := range map[string]string{
		"MigrationStub": MigrationStub,
		"ConfigStub":    ConfigStub,
	} {
		if _, err := parser.ParseFile(token.NewFileSet(), name+".go", source, parser.AllErrors); err != nil {
			t.Errorf("%s does not parse: %v", name, err)
		}
	}
}
