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
	cfg, err := schemaConnector(ctx, root, scope)
	if err != nil {
		return connector.Config{}, err
	}
	if err = provisionDatly(ctx, cfg, scope.Namespace); err != nil {
		return connector.Config{}, err
	}
	return cfg, nil
}

func schemaConnector(ctx context.Context, root string, scope Scope) (connector.Config, error) {
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
	return cfg, nil
}
