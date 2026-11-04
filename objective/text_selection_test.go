package objective

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
	"time"
)

func TestNativeTextSelectionPredicateUsesTypedBoolean(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "selection-observer", []string{"desktop:observe"})
	ctx := auth.WithPrincipal(context.Background(), p)
	for _, selected := range []bool{false, true} {
		reads := 0
		adapter, _ := NewNative(func(_ context.Context, _ auth.Principal, target model.Selector, attribute string) (model.Value, NativeEvidence, error) {
			reads++
			if attribute != "hasFullTextSelection" || target.Locator.Value.String != "display" {
				t.Fatal("selection scope changed")
			}
			return model.Value{Kind: model.BoolValue, Bool: selected}, NativeEvidence{HelperEpoch: "helper", TargetRef: "field", ObservedAt: time.Now()}, nil
		})
		inputs := nativeInputs()
		inputs["attribute"] = model.Value{Kind: model.StringValue, String: "hasFullTextSelection"}
		inputs["expected"] = model.Value{Kind: model.BoolValue, Bool: true}
		result, err := adapter.Evaluate(ctx, p, "valueEquals", inputs)
		want := False
		if selected {
			want = True
		}
		if err != nil || result.Truth != want || reads != 1 {
			t.Fatal("selection predicate not preserved", result, err)
		}
		inputs["expected"] = model.Value{Kind: model.StringValue, String: "true"}
		if _, err = adapter.Evaluate(ctx, p, "valueEquals", inputs); err == nil || reads != 1 {
			t.Fatal("string expectation reached reader")
		}
	}
}
