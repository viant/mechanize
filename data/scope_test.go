package data

import (
	"context"
	"github.com/viant/datly/bootstrap/connector"
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
	scope := Scope{Namespace: strings.Repeat("c", 64)}
	ctx, err := WithScope(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cfg, err := Provision(ctx, root, scope)
	if err != nil {
		t.Fatal(err)
	}
	connections, err := connector.Open(ctx, []connector.Config{cfg}, "user")
	if err != nil {
		t.Fatal(err)
	}
	db, err := connections.SQL.Connector(ctx, "user")
	if err != nil {
		t.Fatal(err)
	}
	// Only infrastructure schema/version manipulation, never product rows.
	if _, err = db.ExecContext(ctx, "DROP TABLE run_variables; PRAGMA user_version=1"); err != nil {
		t.Fatal(err)
	}
	_ = connections.Close()
	cfg, err = Provision(ctx, root, scope)
	if err != nil {
		t.Fatal(err)
	}
	connections, err = connector.Open(ctx, []connector.Config{cfg}, "user")
	if err != nil {
		t.Fatal(err)
	}
	db, err = connections.SQL.Connector(ctx, "user")
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 9 {
		t.Fatalf("migration version %d %v", version, err)
	}
	var count int
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='run_variables'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("migration schema %d %v", count, err)
	}
	// Recreate the exact pre-feature schema boundary and exercise migration 7.
	if _, err = db.ExecContext(ctx, "DROP TABLE chrome_retirement_audit; DROP TABLE chrome_retirement_manifests; DROP TABLE chrome_retirements; PRAGMA user_version=6"); err != nil {
		t.Fatal(err)
	}
	_ = connections.Close()
	cfg, err = Provision(ctx, root, scope)
	if err != nil {
		t.Fatal(err)
	}
	connections, err = connector.Open(ctx, []connector.Config{cfg}, "user")
	if err != nil {
		t.Fatal(err)
	}
	db, err = connections.SQL.Connector(ctx, "user")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 9 {
		t.Fatalf("retirement migration version %d %v", version, err)
	}
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('chrome_retirements','chrome_retirement_manifests','chrome_retirement_audit')").Scan(&count); err != nil || count != 3 {
		t.Fatalf("retirement migration tables %d %v", count, err)
	}
	// Exercise the actual v7-to-v8 boundary with the new table absent.
	if _, err = db.ExecContext(ctx, "DROP TABLE chrome_attempt_bindings; PRAGMA user_version=7"); err != nil {
		t.Fatal(err)
	}
	_ = connections.Close()
	cfg, err = Provision(ctx, root, scope)
	if err != nil {
		t.Fatal(err)
	}
	connections, err = connector.Open(ctx, []connector.Config{cfg}, "user")
	if err != nil {
		t.Fatal(err)
	}
	db, err = connections.SQL.Connector(ctx, "user")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 9 {
		t.Fatalf("binding migration version %d %v", version, err)
	}
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='chrome_attempt_bindings'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("binding migration table %d %v", count, err)
	}
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='chrome_attempt_bindings_fence'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("binding migration fence index %d %v", count, err)
	}
	// Infrastructure-only v8-to-v9 migration with the review table absent.
	if _, err = db.ExecContext(ctx, "DROP TABLE workflow_review_requests; PRAGMA user_version=8"); err != nil {
		t.Fatal(err)
	}
	_ = connections.Close()
	cfg, err = Provision(ctx, root, scope)
	if err != nil {
		t.Fatal(err)
	}
	connections, err = connector.Open(ctx, []connector.Config{cfg}, "user")
	if err != nil {
		t.Fatal(err)
	}
	db, err = connections.SQL.Connector(ctx, "user")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 9 {
		t.Fatalf("review migration version %d %v", version, err)
	}
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='workflow_review_requests'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("review migration table %d %v", count, err)
	}

	if _, err = db.ExecContext(ctx, "PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	_ = connections.Close()
	if _, err = Provision(ctx, root, scope); err == nil {
		t.Fatal("future schema admitted")
	}
}
