package data_test

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/viant/datly/bootstrap/connector"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/datly/standalone"
	"github.com/viant/datly/standalone/config"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/applicationpolicyread"
	"github.com/viant/mechanize/data/applicationpolicywrite"
	"github.com/viant/xdatly/handler"
)

func TestApplicationPolicyCanonicalAndExplicitDeny(t *testing.T) {
	p := data.ApplicationPolicy{DesktopWide: true, Applications: []data.ApplicationPolicyRule{{BundleID: "com.apple.Finder", Modes: []string{}}}}
	if p.Allows("com.apple.Finder", "observe") || !p.Allows("com.apple.Calculator", "control") {
		t.Fatal("desktop explicit denial failed")
	}
	p.DesktopWide = false
	if p.Allows("com.apple.Calculator", "control") {
		t.Fatal("unlisted allowed")
	}
	for _, bad := range []data.ApplicationPolicyRule{{BundleID: "*"}, {BundleID: "com.apple.Finder", Modes: []string{"observe", "observe"}}, {BundleID: "com.apple.Finder", Modes: []string{"unknown"}}} {
		if _, e := data.CanonicalApplicationPolicy(data.ApplicationPolicy{Applications: []data.ApplicationPolicyRule{bad}}); e == nil {
			t.Fatal("invalid rule accepted")
		}
	}
}
func TestApplicationPolicyBoundsAndCanonicalOrder(t *testing.T) {
	p := data.ApplicationPolicy{Applications: []data.ApplicationPolicyRule{{BundleID: "org.example.Z", Modes: []string{"record", "observe", "control"}}, {BundleID: "org.example.A"}}}
	canonical, err := data.CanonicalApplicationPolicy(p)
	if err != nil || canonical.Applications[0].BundleID != "org.example.A" || canonical.Applications[1].Modes[0] != "control" {
		t.Fatalf("canonical order: %+v %v", canonical, err)
	}
	canonical.Applications[1].Modes[0] = "record"
	if p.Applications[0].Modes[0] != "record" || p.Applications[0].Modes[1] != "observe" {
		t.Fatal("canonical result aliases input")
	}
	bad := data.ApplicationPolicy{Applications: make([]data.ApplicationPolicyRule, 257)}
	if _, err = data.CanonicalApplicationPolicy(bad); err == nil {
		t.Fatal("rule bound accepted")
	}
	p.Applications[0].DisplayName = strings.Repeat("x", 513)
	if _, err = data.CanonicalApplicationPolicy(p); err == nil {
		t.Fatal("label bound accepted")
	}
	p.Applications[0].DisplayName = ""
	p.Applications[1].BundleID = p.Applications[0].BundleID
	if _, err = data.CanonicalApplicationPolicy(p); err == nil {
		t.Fatal("duplicate ID accepted")
	}
}

func TestApplicationPolicyGeneratedSQLiteCASAndAuthority(t *testing.T) {
	principal, _ := auth.NewPrincipal("fixture", "", "human", []string{"consent:admin"})
	base := auth.WithPrincipal(context.Background(), principal)
	base, _ = data.WithScope(base, data.Scope{Namespace: principal.Namespace})
	human, err := auth.WithNativeHuman(base)
	if err != nil {
		t.Fatal(err)
	}
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Dir(filepath.Dir(file))
	cfg, err := data.Provision(base, t.TempDir(), data.Scope{Namespace: principal.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	server, err := standalone.New(base, standalone.Options{Config: &config.Config{BaseDir: source, Connector: "user", Connectors: []connector.Config{cfg}, GoBootstrap: &config.Packages{Packages: []string{"github.com/viant/mechanize/data/applicationpolicyread", "github.com/viant/mechanize/data/applicationpolicywrite"}}}, Holders: []any{applicationpolicyread.ApplicationpolicyreadComponent{}, applicationpolicywrite.ApplicationpolicywriteComponent{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	if err = server.Reload(base, 1); err != nil {
		t.Fatal(err)
	}
	invoke := func(ctx context.Context, pkg, method string, input any) (any, error) {
		return server.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: pkg}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: input})
	}
	text := func(s string) *string { return &s }
	number := func(n int) *int { return &n }
	policy, _ := data.ApplicationPolicyJSON(data.ApplicationPolicy{DesktopWide: true, Applications: []data.ApplicationPolicyRule{{BundleID: "com.apple.Finder", Modes: []string{}}}})
	const created = "2026-10-02T00:00:00Z"
	write := func(ctx context.Context, rev int, json, at string, mutate ...func(*applicationpolicywrite.PolicyRecord)) error {
		proof := data.ApplicationPolicyAuthority{Namespace: principal.Namespace, ExpectedRevision: rev, PolicyJSON: json, CreatedAt: created, UpdatedAt: at}
		ctx = data.WithApplicationPolicyAuthority(ctx, proof)
		row := &applicationpolicywrite.PolicyRecord{}
		row.SetNamespace(text(principal.Namespace))
		row.SetId(text(data.ApplicationPolicyID))
		row.SetRevision(number(rev))
		row.SetPolicyJson(text(json))
		row.SetCreatedAt(text(created))
		row.SetUpdatedAt(text(at))
		for _, change := range mutate {
			change(row)
		}
		input := &applicationpolicywrite.WriteApplicationPolicyInput{}
		input.SetNamespace(principal.Namespace)
		input.SetExpectedRevision(rev)
		input.SetApplicationpolicywrite([]*applicationpolicywrite.PolicyRecord{row})
		var outcome handler.Outcome
		_, e := server.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/applicationpolicywrite", Name: "applicationpolicywrite"}, Route: spec.RouteRef{Method: "PATCH", Path: "/internal/data/applicationpolicywrite"}}, Input: input, Completion: func(v handler.Outcome) { outcome = v }})
		if e == nil && !outcome.CommitConfirmed() {
			t.Fatal("write not committed")
		}
		return e
	}
	if err = write(base, 0, policy, created); err == nil {
		t.Fatal("scope-only caller accepted")
	}
	if err = write(human, 0, policy, created); err != nil {
		t.Fatal(err)
	}
	read := func(ns string) (*applicationpolicyread.ReadApplicationPolicyOutput, error) {
		input := &applicationpolicyread.ReadApplicationPolicyInput{}
		input.SetNamespace(ns)
		v, e := invoke(base, "applicationpolicyread", "GET", input)
		if e != nil {
			return nil, e
		}
		return v.(*applicationpolicyread.ReadApplicationPolicyOutput), nil
	}
	first, err := read(principal.Namespace)
	if err != nil || len(first.Data) != 1 || *first.Data[0].Revision != 1 {
		t.Fatalf("create/read: %+v %v", first, err)
	}
	next, _ := data.ApplicationPolicyJSON(data.ApplicationPolicy{Applications: []data.ApplicationPolicyRule{{BundleID: "com.apple.Calculator", Modes: []string{"control", "observe"}}}})
	if err = write(human, 1, next, "2026-10-02T00:01:00Z"); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*applicationpolicywrite.PolicyRecord){
		func(row *applicationpolicywrite.PolicyRecord) { row.SetPolicyJson(text(policy)) },
		func(row *applicationpolicywrite.PolicyRecord) { row.SetCreatedAt(text("2026-10-02T00:09:00Z")) },
		func(row *applicationpolicywrite.PolicyRecord) { row.SetId(text("other")) },
		func(row *applicationpolicywrite.PolicyRecord) { row.SetNamespace(text(strings.Repeat("b", 64))) },
	} {
		if err = write(human, 2, next, "2026-10-02T00:02:00Z", mutate); err == nil {
			t.Fatal("untrusted row escaped exact proof")
		}
	}
	if err = write(human, 1, policy, "2026-10-02T00:02:00Z"); err == nil {
		t.Fatal("stale CAS accepted")
	}
	last, err := read(principal.Namespace)
	if err != nil || *last.Data[0].Revision != 2 || *last.Data[0].PolicyJson != next || *last.Data[0].CreatedAt != created || *last.Data[0].UpdatedAt != "2026-10-02T00:01:00Z" {
		t.Fatalf("rollback/read: %+v %v", last, err)
	}
	other, _ := auth.NewPrincipal("fixture", "", "other", nil)
	if _, err = read(other.Namespace); err == nil {
		t.Fatal("cross namespace read accepted")
	}
}
