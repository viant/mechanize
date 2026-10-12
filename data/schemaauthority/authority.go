// Package schemaauthority carries trusted infrastructure scope, never caller SQL.
package schemaauthority

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
)

const Version = 15

var namespace = regexp.MustCompile(`^[0-9a-f]{64}$`)

type key struct{}
type Authority struct {
	name       string
	guard      func(context.Context) error
	migrations fs.FS
}

// With installs host-owned embedded migrations in one scoped bootstrap context.
// No component input can supply scripts, connector names, paths or capabilities.
func With(ctx context.Context, name string, guard func(context.Context) error, migrations fs.FS) (context.Context, error) {
	if !namespace.MatchString(name) || guard == nil || migrations == nil || guard(ctx) != nil {
		return nil, errors.New("trusted schema scope required")
	}
	return context.WithValue(ctx, key{}, &Authority{name: name, guard: guard, migrations: migrations}), nil
}
func Require(ctx context.Context, name string) (*Authority, error) {
	a, ok := ctx.Value(key{}).(*Authority)
	if !ok || a == nil || a.name != name || !namespace.MatchString(name) || ctx.Err() != nil || a.guard(ctx) != nil {
		return nil, errors.New("trusted schema scope required")
	}
	return a, nil
}
func (a *Authority) Migration(version int) (string, error) {
	if a == nil || version < 1 || version > Version {
		return "", errors.New("unsupported schema migration")
	}
	raw, e := fs.ReadFile(a.migrations, fmt.Sprintf("schema/%03d.sql", version))
	return string(raw), e
}
