package data

import (
	"context"
	"encoding/json"
	dexec "github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/data/schemaapply"
	"github.com/viant/mechanize/data/schemalegacyread"
	"strings"
	"testing"
)

func TestCredentialRetirementMigrationPreservesUnknownHistory(t *testing.T) {
	scope := Scope{Namespace: strings.Repeat("a", 64)}
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
	for version := 0; version < 13; version++ {
		if e = applySchemaVersion(authorized, server, scope.Namespace, version); e != nil {
			t.Fatal(e)
		}
	}
	if outcome, e := fixtureSchemaCall(authorized, server, scope.Namespace, "legacyUnknown"); e != nil || !outcome.CommitConfirmed() {
		t.Fatal("Datly legacy fixture failed", e)
	}
	snapshot := func() string {
		in := &schemalegacyread.SchemaLegacyReadInput{}
		in.SetNamespace(scope.Namespace)
		result, e := server.InvokeComponent(authorized, dexec.ComponentRequest{Target: dexec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/schemalegacyread", Name: "SchemaLegacyRead"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/schemalegacyread"}}, Input: in})
		if e != nil {
			t.Fatal(e)
		}
		out, ok := result.(*schemalegacyread.SchemaLegacyReadOutput)
		if !ok || len(out.Data) != 1 || out.Data[0].AuditCount != 2 || out.Data[0].BlockedCount != 1 {
			t.Fatal("scoped legacy history inventory mismatch")
		}
		raw, e := json.Marshal(out.Data)
		if e != nil {
			t.Fatal(e)
		}
		return string(raw)
	}
	before := snapshot()
	if _, e = Provision(ctx, root, scope); e != nil {
		t.Fatal(e)
	}
	if snapshot() != before {
		t.Fatal("migration changed UNKNOWN/protection/process/purpose/revision/audit history")
	}
	state, e := schemaapply.Read(authorized, server, scope.Namespace)
	if e != nil || state.Version != 15 || state.ForeignKeyViolations != 0 {
		t.Fatal("migration version or audit foreign key changed", e)
	}
}
