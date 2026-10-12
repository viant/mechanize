package objective

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
	"time"
)

func TestWebIndexedPredicatePreservesPrivateScopeAndRequiresClosedPair(t *testing.T) {
	ctx, p := webActor(t)
	pinned := webPinnedIdentity()
	reads := 0
	adapter, e := NewWebWithOptions(WebOptions{ResolveIdentity: func(context.Context, auth.Principal, string) (WebIdentity, error) { return pinned, nil }, Read: func(_ context.Context, actual auth.Principal, target model.Selector, attribute string, id WebIdentity) (model.Value, WebEvidence, error) {
		reads++
		if target.Cardinality != "nth" || target.Index == nil || *target.Index != 1 || target.Order != "document" || target.Surface.TabID != "p1/b1/7" || id != pinned {
			t.Fatal("indexed postcondition changed private document scope")
		}
		return model.Value{Kind: model.StringValue, String: "ready"}, WebEvidence{Owner: actual.Namespace, ClientID: actual.ClientID, Identity: id, RequestID: "read", ObservedAt: time.Now()}, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	inputs := webAuthoredInputs()
	inputs["index"] = model.Value{Kind: model.NumberValue, Number: 1}
	inputs["order"] = model.Value{Kind: model.StringValue, String: "document"}
	result, e := adapter.Evaluate(ctx, p, "valueEquals", inputs)
	if e != nil || result.Truth != True || reads != 1 {
		t.Fatal("indexed private postcondition unavailable", e)
	}
	for _, mode := range []string{"missingIndex", "missingOrder", "negative", "oversize", "tree", "stringIndex", "ancestor"} {
		bad := map[string]model.Value{}
		for key, value := range inputs {
			bad[key] = value
		}
		switch mode {
		case "missingIndex":
			delete(bad, "index")
		case "missingOrder":
			delete(bad, "order")
		case "negative":
			bad["index"] = model.Value{Kind: model.NumberValue, Number: -1}
		case "oversize":
			bad["index"] = model.Value{Kind: model.NumberValue, Number: 1000}
		case "tree":
			bad["order"] = model.Value{Kind: model.StringValue, String: "tree"}
		case "stringIndex":
			bad["index"] = model.Value{Kind: model.StringValue, String: "1"}
		case "ancestor":
			bad["ancestor"] = model.Value{Kind: model.StringValue, String: "foreign"}
		}
		before := reads
		if _, err := adapter.Evaluate(ctx, p, "valueEquals", bad); err == nil || reads != before {
			t.Fatal("unqualified indexed predicate reached reader", mode)
		}
	}
}
