package data

import (
	"context"
	"fmt"
	"github.com/viant/mechanize/data/schemaapply"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopeAndProvisionPaths(t *testing.T) {
	for _, name := range []string{"", "../other", "someone@example.com", strings.Repeat("A", 64)} {
		if _, err := WithScope(context.Background(), Scope{Namespace: name}); err == nil {
			t.Fatalf("namespace %q accepted", name)
		}
	}
	scope := Scope{Namespace: strings.Repeat("a", 64)}
	ctx, err := WithScope(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RequireScope(context.Background(), scope.Namespace); err == nil {
		t.Fatal("missing scope accepted")
	}
	if _, err = RequireScope(ctx, strings.Repeat("b", 64)); err == nil {
		t.Fatal("foreign scope accepted")
	}
	root := t.TempDir()
	cfg, err := Provision(ctx, root, scope)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Name != "user" || !strings.Contains(cfg.DSN, "_synchronous=FULL") {
		t.Fatalf("unexpected connector %+v", cfg)
	}
	path := filepath.Join(root, "users", scope.Namespace, "state.sqlite")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("database mode %v", info.Mode())
	}
	root2 := t.TempDir()
	if err = os.Symlink(root, filepath.Join(root2, "users")); err != nil {
		t.Fatal(err)
	}
	if _, err = Provision(ctx, root2, scope); err == nil {
		t.Fatal("storage symlink accepted")
	}
}

func TestInfrastructureSchemaMigrationAndFutureVersion(t *testing.T) {
	for _, prior := range []int{1, 6, 7, 8, 10, 13} {
		t.Run(fmt.Sprint(prior), func(t *testing.T) {
			scope := Scope{Namespace: strings.Repeat("c", 64)}
			ctx, e := WithScope(context.Background(), scope)
			if e != nil {
				t.Fatal(e)
			}
			root := t.TempDir()
			cfg, e := schemaConnector(ctx, root, scope)
			if e != nil {
				t.Fatal(e)
			}
			authorized, e := schemaContext(ctx, scope.Namespace)
			if e != nil {
				t.Fatal(e)
			}
			server := schemaTestHost(t, authorized, cfg)
			for version := 0; version < prior; version++ {
				if e = applySchemaVersion(authorized, server, scope.Namespace, version); e != nil {
					t.Fatal(e)
				}
			}
			before, e := schemaapply.Read(authorized, server, scope.Namespace)
			if e != nil || before.Version != prior {
				t.Fatal("prior schema boundary unavailable", e)
			}
			if _, e = Provision(ctx, root, scope); e != nil {
				t.Fatal(e)
			}
			after, e := schemaapply.Read(authorized, server, scope.Namespace)
			if e != nil || after.Version != 15 || after.VariablesTable != 1 || after.RetirementTables != 3 || after.AttemptBindingsTable != 1 || after.AttemptFenceIndex != 1 || after.WorkflowReviewsTable != 1 || after.PurposeColumns != 1 || after.LineageTriggers != 2 || after.ForeignKeyViolations != 0 {
				t.Fatal("generated schema metadata failed migration assertions", after, e)
			}
		})
	}
}
