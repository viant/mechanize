package data

import (
	"context"
	"embed"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
	"github.com/viant/datly/bootstrap/connector"
	_ "github.com/viant/sqlx/metadata/product/sqlite"
)

//go:embed schema/*.sql
var schema embed.FS

// Provision is the infrastructure-only schema/connector path. The host owns the
// returned Datly connector configuration; request inputs cannot choose its DSN.
func Provision(ctx context.Context, root string, scope Scope) (connector.Config, error) {
	if _, err := RequireScope(ctx, scope.Namespace); err != nil {
		return connector.Config{}, err
	}
	if !filepath.IsAbs(root) {
		return connector.Config{}, fmt.Errorf("absolute trusted storage root required")
	}
	for _, path := range []string{filepath.Join(root, "users"), filepath.Join(root, "users", scope.Namespace), filepath.Join(root, "users", scope.Namespace, "state.sqlite")} {
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return connector.Config{}, fmt.Errorf("storage symlink rejected")
		}
		if err != nil && !os.IsNotExist(err) {
			return connector.Config{}, err
		}
	}
	dir := filepath.Join(root, "users", scope.Namespace)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return connector.Config{}, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return connector.Config{}, err
	}
	path := filepath.Join(dir, "state.sqlite")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return connector.Config{}, err
	}
	_ = f.Close()
	if err = os.Chmod(path, 0600); err != nil {
		return connector.Config{}, err
	}
	cfg := connector.Config{Name: "user", Driver: "sqlite3", DSN: (&url.URL{Scheme: "file", Path: path, RawQuery: "_foreign_keys=on&_journal_mode=WAL&_synchronous=FULL&_busy_timeout=5000"}).String(), MaxOpenConns: 1, MaxIdleConns: 1}
	connections, err := connector.Open(ctx, []connector.Config{cfg}, "user")
	if err != nil {
		return connector.Config{}, err
	}
	defer connections.Close()
	db, err := connections.SQL.Connector(ctx, "user")
	if err != nil {
		return connector.Config{}, err
	}
	var version int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return connector.Config{}, err
	}
	if version > 9 {
		return connector.Config{}, fmt.Errorf("unsupported future state schema version")
	}
	ddl, _ := schema.ReadFile("schema/001.sql")
	if _, err = db.ExecContext(ctx, string(ddl)); err != nil {
		return connector.Config{}, err
	}
	if version < 2 {
		migration, _ := schema.ReadFile("schema/002.sql")
		transaction, err := db.BeginTx(ctx, nil)
		if err != nil {
			return connector.Config{}, err
		}
		if _, err = transaction.ExecContext(ctx, string(migration)); err != nil {
			_ = transaction.Rollback()
			return connector.Config{}, err
		}
		if err = transaction.Commit(); err != nil {
			return connector.Config{}, err
		}
	}
	if version < 3 {
		migration, _ := schema.ReadFile("schema/003.sql")
		transaction, err := db.BeginTx(ctx, nil)
		if err != nil {
			return connector.Config{}, err
		}
		if _, err = transaction.ExecContext(ctx, string(migration)); err != nil {
			_ = transaction.Rollback()
			return connector.Config{}, err
		}
		if err = transaction.Commit(); err != nil {
			return connector.Config{}, err
		}
	}
	if version < 4 {
		migration, _ := schema.ReadFile("schema/004.sql")
		transaction, err := db.BeginTx(ctx, nil)
		if err != nil {
			return connector.Config{}, err
		}
		if _, err = transaction.ExecContext(ctx, string(migration)); err != nil {
			_ = transaction.Rollback()
			return connector.Config{}, err
		}
		if err = transaction.Commit(); err != nil {
			return connector.Config{}, err
		}
	}
	if version < 5 {
		migration, _ := schema.ReadFile("schema/005.sql")
		transaction, err := db.BeginTx(ctx, nil)
		if err != nil {
			return connector.Config{}, err
		}
		if _, err = transaction.ExecContext(ctx, string(migration)); err != nil {
			_ = transaction.Rollback()
			return connector.Config{}, err
		}
		if err = transaction.Commit(); err != nil {
			return connector.Config{}, err
		}
	}
	if version < 6 {
		migration, readErr := schema.ReadFile("schema/006.sql")
		if readErr != nil {
			return connector.Config{}, readErr
		}
		transaction, err := db.BeginTx(ctx, nil)
		if err != nil {
			return connector.Config{}, err
		}
		if _, err = transaction.ExecContext(ctx, string(migration)); err != nil {
			_ = transaction.Rollback()
			return connector.Config{}, err
		}
		if err = transaction.Commit(); err != nil {
			return connector.Config{}, err
		}
	}

	if version < 7 {
		migration, readErr := schema.ReadFile("schema/007.sql")
		if readErr != nil {
			return connector.Config{}, readErr
		}
		transaction, err := db.BeginTx(ctx, nil)
		if err != nil {
			return connector.Config{}, err
		}
		if _, err = transaction.ExecContext(ctx, string(migration)); err != nil {
			_ = transaction.Rollback()
			return connector.Config{}, err
		}
		if err = transaction.Commit(); err != nil {
			return connector.Config{}, err
		}
	}

	if version < 8 {
		migration, readErr := schema.ReadFile("schema/008.sql")
		if readErr != nil {
			return connector.Config{}, readErr
		}
		transaction, err := db.BeginTx(ctx, nil)
		if err != nil {
			return connector.Config{}, err
		}
		if _, err = transaction.ExecContext(ctx, string(migration)); err != nil {
			_ = transaction.Rollback()
			return connector.Config{}, err
		}
		if err = transaction.Commit(); err != nil {
			return connector.Config{}, err
		}
	}

	if version < 9 {
		migration, readErr := schema.ReadFile("schema/009.sql")
		if readErr != nil {
			return connector.Config{}, readErr
		}
		transaction, err := db.BeginTx(ctx, nil)
		if err != nil {
			return connector.Config{}, err
		}
		if _, err = transaction.ExecContext(ctx, string(migration)); err != nil {
			_ = transaction.Rollback()
			return connector.Config{}, err
		}
		if err = transaction.Commit(); err != nil {
			return connector.Config{}, err
		}
	}

	return cfg, nil
}
