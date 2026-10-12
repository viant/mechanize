package chrome

import (
	"context"
	"github.com/viant/mechanize/model"
	"testing"
)

func TestWebIndexedLocatorCompilesOnlyExplicitDocumentNth(t *testing.T) {
	index := 1
	selector := model.Selector{Surface: model.Surface{Kind: "web", Origin: "https://fixture.test"}, Locator: &model.Locator{Strategy: "role", Value: model.Value{Kind: model.StringValue, String: "button"}, Exact: true}, Cardinality: "nth", Index: &index, Order: "document"}
	locator, e := compileLocator(selector, nil)
	if e != nil || locator.Index == nil || *locator.Index != 1 || locator.Order != "document" {
		t.Fatal("explicit web nth unavailable", e)
	}
	index = 2
	if *locator.Index != 1 {
		t.Fatal("compiled locator retained mutable model index")
	}
	for _, mode := range []string{"all", "missingOrder", "tree", "negative", "ancestor"} {
		bad := selector
		value := 0
		bad.Index = &value
		switch mode {
		case "all":
			bad.Cardinality = "all"
		case "missingOrder":
			bad.Order = ""
		case "tree":
			bad.Order = "tree"
		case "negative":
			value = -1
		case "ancestor":
			ancestor := selector
			bad.Ancestor = &ancestor
		}
		if _, e := compileLocator(bad, nil); e == nil {
			t.Fatal("unsupported ordering/scope allowed", mode)
		}
	}
}
func TestWebIndexedLocatorNeverFallsBackToLegacyExtension(t *testing.T) {
	b := fixtureBroker(t, enrollment(principal(t, "indexed"), "p"))
	b.mu.Lock()
	c := b.channels[channelKey("p", "browser1")]
	b.mu.Unlock()
	index := 0
	if _, e := b.callPrepared(context.Background(), c, Command{Action: "read", Locator: &Locator{Strategy: "role", Value: "button", Exact: true, Index: &index, Order: "document"}}, false, nil); e == nil {
		t.Fatal("unqualified indexed selector reached legacytransport")
	}
}
