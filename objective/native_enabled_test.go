package objective

import (
	"context"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestNativeEnabledUsesBooleanEvidence(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	for _, enabled := range []bool{false, true} {
		a, _ := NewNative(func(_ context.Context, _ auth.Principal, _ model.Selector, attribute string) (model.Value, NativeEvidence, error) {
			if attribute != "enabled" {
				t.Fatal("wrong metadata read")
			}
			return model.Value{Kind: model.BoolValue, Bool: enabled}, NativeEvidence{HelperEpoch: "fixture", TargetRef: "target", ObservedAt: time.Now()}, nil
		})
		inputs := nativeInputs()
		inputs["attribute"] = model.Value{Kind: model.StringValue, String: "enabled"}
		inputs["expected"] = model.Value{Kind: model.BoolValue, Bool: true}
		result, err := a.Evaluate(ctx, p, "valueEquals", inputs)
		want := False
		if enabled {
			want = True
		}
		if err != nil || result.Truth != want {
			t.Fatalf("enabled=%v result=%+v error=%v", enabled, result, err)
		}
		inputs["expected"] = model.Value{Kind: model.StringValue, String: "true"}
		if _, err = a.Evaluate(ctx, p, "valueEquals", inputs); err == nil {
			t.Fatal("string used as boolean expectation")
		}
	}
}
