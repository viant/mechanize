package durable

import (
	"context"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"testing"
)

func TestRetirementComponentExactExposure(t *testing.T) {
	for _, entry := range []struct{ pkg, name, method string }{{"chromeretirementget", "LoadChromeRetirement", "GET"}, {"chromeretirementwrite", "WriteChromeRetirement", "PATCH"}, {"chromeattemptbindinglist", "ListChromeAttemptBindings", "GET"}, {"loadplan", "LoadPlan", "GET"}} {
		base := exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + entry.pkg, Name: entry.name}, Route: spec.RouteRef{Method: entry.method, Path: "/internal/data/" + entry.pkg}}}
		if !retirementComponentAllowed(base) {
			t.Fatal("intended generated contract rejected")
		}
		for _, field := range []string{"name", "scope", "method", "path", "kind"} {
			bad := base
			switch field {
			case "name":
				bad.Target.Component.Name = "Other"
			case "scope":
				bad.Target.Component.Scope += "other"
			case "method":
				bad.Target.Route.Method = "POST"
			case "path":
				bad.Target.Route.Path += "other"
			case "kind":
				bad.Target.Component.Kind = "other"
			}
			if retirementComponentAllowed(bad) {
				t.Fatal("forged target accepted", field)
			}
		}
	}
}
func TestRetirementComponentCannotUseOrdinaryUnheldContext(t *testing.T) {
	ctx, p := privateActor(t)
	b := &Builder{}
	req := exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/chromeretirementget", Name: "LoadChromeRetirement"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/chromeretirementget"}}}
	if _, err := b.invokeRetirementComponent(ctx, p, req); err == nil {
		t.Fatal("unheld invocation accepted")
	}
	held, revoke := b.withHeldUserLock(ctx, p, &userHost{})
	defer revoke()
	called := false
	if err := b.WithChromeRetirementComponents(held, p, func(context.Context, RetirementComponentInvoker) error { called = true; return nil }); err == nil || called {
		t.Fatal("nested callback accepted")
	}
}
