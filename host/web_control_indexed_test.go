package host

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestWebMutationIndexedLocatorRequiresExplicitProviderQualification(t *testing.T) {
	index := 0
	step := model.Step{ID: "indexed", Action: "element.press", TimeoutMs: 1000, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"operation": {Kind: model.StringValue, String: "fixture"}}}, Target: model.Selector{Surface: model.Surface{Kind: "web", Origin: "https://fixture.test"}, Locator: &model.Locator{Strategy: "role", Value: model.Value{Kind: model.StringValue, String: "button"}, Exact: true}, Cardinality: "nth", Index: &index, Order: "document"}}
	if e := webMutationStep(step); e != nil {
		t.Fatal("typed indexed mutation unavailable", e)
	}
	ready := WebControlReadiness{Locators: []string{"role"}}
	if supportsWebStepLocator(ready, step) {
		t.Fatal("legacy provider claims indexed mutation")
	}
	ready.IndexedQueryQualified = true
	if !supportsWebStepLocator(ready, step) {
		t.Fatal("qualified indexed provider rejected")
	}
	step.Target.Order = "tree"
	if webMutationStep(step) == nil {
		t.Fatal("web tree ordering allowed")
	}
	step.Target.Order = "document"
	step.Target.Cardinality = "all"
	step.Target.Limit = 10
	step.Target.Index = nil
	if webMutationStep(step) == nil {
		t.Fatal("unsupported plural mutations allowed")
	}
}
