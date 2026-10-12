package data

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/viant/datly/bootstrap/connector"
	dexec "github.com/viant/datly/exec"
	rhandler "github.com/viant/datly/runtime/handler"
	"github.com/viant/datly/runtime/handler/custom"
	"github.com/viant/datly/spec"
	"github.com/viant/datly/standalone"
	"github.com/viant/datly/standalone/config"
	"github.com/viant/mechanize/data/schemaapply"
	"github.com/viant/mechanize/data/schemaauthority"
	"github.com/viant/mechanize/data/schemalegacyread"
	"github.com/viant/mechanize/data/schemasnapshot"
	"github.com/viant/xdatly"
	"github.com/viant/xdatly/handler"
)

// Fixed, test-only Datly component: the input selects a named fixture, never SQL.
type SchemaFixtureComponent struct {
	Fixture xdatly.Component[SchemaFixtureInput, SchemaFixtureOutput] `component:"Fixture,path=/internal/test/schema-fixture,method=POST,connector=user,handler=NewSchemaFixture"`
}

func (SchemaFixtureComponent) DatlyHandler(name string) func() (rhandler.TypedHandler, error) {
	if name == "NewSchemaFixture" {
		return custom.Factory(NewSchemaFixture)
	}
	return nil
}

type SchemaFixtureInput struct {
	Namespace string `parameter:"Namespace,kind=query,in=namespace,required"`
	Mode      string `parameter:"Mode,kind=body,in=mode,required"`
}
type SchemaFixtureOutput struct {
	Mode string `json:"mode"`
}
type schemaFixture struct{}

func NewSchemaFixture() handler.Contract[SchemaFixtureInput, SchemaFixtureOutput] {
	return &schemaFixture{}
}
func (*schemaFixture) Exec(ctx context.Context, session handler.Session, in *SchemaFixtureInput, out *SchemaFixtureOutput) error {
	if _, e := schemaauthority.Require(ctx, in.Namespace); e != nil {
		return e
	}
	deps := struct {
		DML handler.DML `bind:"kind=dml,required"`
	}{}
	if e := session.Binder().Bind(ctx, &deps); e != nil {
		return e
	}
	switch in.Mode {
	case "futureVersion":
		if e := deps.DML.Execute("PRAGMA user_version=99"); e != nil {
			return e
		}
	case "legacyUnknown":
		id, revision, purpose := strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
		attempt := strings.Repeat("e", 64)
		if e := deps.DML.Execute("INSERT INTO credential_delivery_preparations VALUES(?,?,?,?,?,?,?,?,?,?,?)", in.Namespace, "actor", "session", id, "grant", purpose, "https://fixture.invalid", revision, "held", 1, "2026-01-01T00:00:00Z"); e != nil {
			return e
		}
		if e := deps.DML.Execute("INSERT INTO credential_delivery_attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", in.Namespace, "actor", "session", attempt, id, revision, "grant", "https://fixture.invalid", "profile", "browser", "document", 1, 7, "broker", "channel", strings.Repeat("f", 64), "lease", 1, "123:456", "234:567", "unknown", "held", 2, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z", purpose); e != nil {
			return e
		}
		for rev := 1; rev <= 2; rev++ {
			if e := deps.DML.Execute("INSERT INTO credential_delivery_audit VALUES(?,?,?,?,?,?,?)", in.Namespace, "actor", attempt, rev, "unknown", "held", "2026-01-01T00:00:00Z"); e != nil {
				return e
			}
		}
	case "rollback":
		if e := deps.DML.Execute("CREATE TABLE schema_fixture_rollback(id INTEGER PRIMARY KEY)"); e != nil {
			return e
		}
		if e := deps.DML.Execute("PRAGMA user_version=99"); e != nil {
			return e
		}
		if e := deps.DML.Execute("INSERT INTO schema_fixture_absent_table VALUES(1)"); e != nil {
			return e
		}
	default:
		return errors.New("unsupported fixed schema fixture")
	}
	out.Mode = in.Mode
	return nil
}
func schemaTestHost(t *testing.T, ctx context.Context, cfg connector.Config) *standalone.Server {
	t.Helper()
	server, e := standalone.New(ctx, standalone.Options{Config: &config.Config{Connector: "user", Connectors: []connector.Config{cfg}, GoBootstrap: &config.Packages{LinkedOnly: true, Packages: []string{schemaapply.Scope, "github.com/viant/mechanize/data/schemasnapshot", "github.com/viant/mechanize/data/schemalegacyread", "github.com/viant/mechanize/data"}}}, Holders: []any{schemaapply.Component{}, schemasnapshot.SchemaSnapshotComponent{}, schemalegacyread.SchemaLegacyReadComponent{}, SchemaFixtureComponent{}}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	if e = server.Reload(ctx, 1); e != nil {
		t.Fatal(e)
	}
	return server
}
func fixtureSchemaCall(ctx context.Context, server *standalone.Server, ns, mode string) (handler.Outcome, error) {
	var outcome handler.Outcome
	_, e := server.InvokeComponent(ctx, dexec.ComponentRequest{Target: dexec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data", Name: "Fixture"}, Route: spec.RouteRef{Method: "POST", Path: "/internal/test/schema-fixture"}}, Input: &SchemaFixtureInput{Namespace: ns, Mode: mode}, Completion: func(o handler.Outcome) { outcome = o }})
	return outcome, e
}
func TestDatlyProvisionEmptyNoopRollbackAndFutureVersion(t *testing.T) {
	scope := Scope{Namespace: strings.Repeat("d", 64)}
	ctx, e := WithScope(context.Background(), scope)
	if e != nil {
		t.Fatal(e)
	}
	// Connector construction is infrastructure configuration; only Datly components
	// open/read/mutate this disposable database, including fixture setup/assertions.
	path := filepath.Join(t.TempDir(), "bootstrap.sqlite")
	cfg := connector.Config{Name: "user", Driver: "sqlite3", DSN: (&url.URL{Scheme: "file", Path: path, RawQuery: "_foreign_keys=on&_journal_mode=WAL&_synchronous=FULL&_busy_timeout=5000"}).String(), MaxOpenConns: 1, MaxIdleConns: 1}
	authorized, e := schemaContext(ctx, scope.Namespace)
	if e != nil {
		t.Fatal(e)
	}
	server := schemaTestHost(t, authorized, cfg)
	empty, e := schemaapply.Read(authorized, server, scope.Namespace)
	if e != nil || empty.Version != 0 || empty.ObjectCount != 0 {
		t.Fatal("empty generated schema read", empty, e)
	}
	if _, e = schemaapply.Read(context.Background(), server, scope.Namespace); e == nil {
		t.Fatal("schema reader accepted missing infrastructure authority")
	}
	for version := 0; version < schemaauthority.Version; version++ {
		if e = applySchemaVersion(authorized, server, scope.Namespace, version); e != nil {
			t.Fatalf("migration %d: %v", version+1, e)
		}
	}
	current, e := schemaapply.Read(authorized, server, scope.Namespace)
	if e != nil || current.Version != 15 || current.ForeignKeys != 1 || current.JournalMode != "wal" || current.Synchronous != 2 || current.ObjectCount == 0 {
		t.Fatal("Datly migration/settings readback", current, e)
	}
	if e = provisionDatly(ctx, cfg, scope.Namespace); e != nil {
		t.Fatal("existing15 failed", e)
	}
	unchanged, e := schemaapply.Read(authorized, server, scope.Namespace)
	if e != nil || unchanged != current {
		t.Fatal("existing15 was not a no-op", unchanged, e)
	}
	if outcome, e := fixtureSchemaCall(authorized, server, scope.Namespace, "rollback"); e == nil || outcome.CommitConfirmed() {
		t.Fatal("failing migration fixture committed")
	}
	after, e := schemaapply.Read(authorized, server, scope.Namespace)
	if e != nil || after != current {
		t.Fatal("DDL/version did not roll back together", after, e)
	}
	if outcome, e := fixtureSchemaCall(authorized, server, scope.Namespace, "futureVersion"); e != nil || !outcome.CommitConfirmed() {
		t.Fatal("future fixture failed", e)
	}
	if e = provisionDatly(ctx, cfg, scope.Namespace); e == nil {
		t.Fatal("future schema accepted")
	}
	future, e := schemaapply.Read(authorized, server, scope.Namespace)
	if e != nil || future.Version != 99 || future.ObjectCount != current.ObjectCount {
		t.Fatal("future rejection changed schema", future, e)
	}
}

func TestDatlyProvisionConcurrentSameNamespace(t *testing.T) {
	scope := Scope{Namespace: strings.Repeat("e", 64)}
	ctx, e := WithScope(context.Background(), scope)
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	start := make(chan struct{})
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { <-start; _, e := Provision(ctx, root, scope); done <- e }()
	}
	close(start)
	// A contender may lose SQLite's writer lock. A complete authorized retry must
	// converge without a partial schema, duplicate migration, or missing trigger.
	for i := 0; i < 2; i++ {
		if e := <-done; e != nil {
			t.Log("concurrent bootstrap refused; checking clean retry")
		}
	}
	cfg, e := Provision(ctx, root, scope)
	if e != nil {
		t.Fatal("concurrent bootstrap did not recover", e)
	}
	authorized, e := schemaContext(ctx, scope.Namespace)
	if e != nil {
		t.Fatal(e)
	}
	server := schemaTestHost(t, authorized, cfg)
	state, e := schemaapply.Read(authorized, server, scope.Namespace)
	if e != nil || state.Version != 15 || state.LineageTriggers != 2 || state.PurposeColumns != 1 || state.ForeignKeyViolations != 0 || state.RetirementTables != 3 {
		t.Fatal("concurrent migration left incomplete schema", state, e)
	}
}
