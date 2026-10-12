package data

import (
	"context"
	"errors"

	"github.com/viant/datly/bootstrap/connector"
	dexec "github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/datly/standalone"
	"github.com/viant/datly/standalone/config"
	"github.com/viant/mechanize/data/schemaapply"
	"github.com/viant/mechanize/data/schemaauthority"
	"github.com/viant/mechanize/data/schemasnapshot"
	"github.com/viant/xdatly/handler"
)

func schemaContext(ctx context.Context, namespace string) (context.Context, error) {
	return schemaauthority.With(ctx, namespace, func(c context.Context) error { _, e := RequireScope(c, namespace); return e }, schema)
}
func openSchemaHost(ctx context.Context, cfg connector.Config) (*standalone.Server, error) {
	server, e := standalone.New(ctx, standalone.Options{Config: &config.Config{Connector: "user", Connectors: []connector.Config{cfg}, GoBootstrap: &config.Packages{LinkedOnly: true, Packages: []string{schemaapply.Scope, "github.com/viant/mechanize/data/schemasnapshot"}}}, Holders: []any{schemaapply.Component{}, schemasnapshot.SchemaSnapshotComponent{}}})
	if e != nil {
		return nil, e
	}
	if e = server.Reload(ctx, 1); e != nil {
		_ = server.Shutdown(context.Background())
		return nil, e
	}
	return server, nil
}
func applySchemaVersion(ctx context.Context, server *standalone.Server, namespace string, expected int) error {
	var outcome handler.Outcome
	_, e := server.InvokeComponent(ctx, dexec.ComponentRequest{Target: dexec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: schemaapply.Scope, Name: "Apply"}, Route: spec.RouteRef{Method: "POST", Path: "/internal/data/schemaapply"}}, Input: &schemaapply.Input{Namespace: namespace, Expected: expected, Version: expected + 1}, Completion: func(o handler.Outcome) { outcome = o }})
	if e != nil {
		return e
	}
	if !outcome.CommitConfirmed() {
		return errors.New("schema migration commit unconfirmed")
	}
	state, e := schemaapply.Read(ctx, server, namespace)
	if e != nil {
		return e
	}
	if state.Version != expected+1 {
		return errors.New("schema migration readback differs")
	}
	return nil
}
func provisionDatly(ctx context.Context, cfg connector.Config, namespace string) error {
	ctx, e := schemaContext(ctx, namespace)
	if e != nil {
		return e
	}
	server, e := openSchemaHost(ctx, cfg)
	if e != nil {
		return e
	}
	defer server.Shutdown(context.Background())
	state, e := schemaapply.Read(ctx, server, namespace)
	if e != nil {
		return e
	}
	if state.Version < 0 || state.Version > schemaauthority.Version {
		return errors.New("unsupported future state schema version")
	}
	if state.ForeignKeys != 1 || state.JournalMode != "wal" || state.Synchronous != 2 {
		return errors.New("required Datly connection durability settings unavailable")
	}
	for version := state.Version; version < schemaauthority.Version; version++ {
		if e = applySchemaVersion(ctx, server, namespace, version); e != nil {
			return e
		}
	}
	return nil
}
