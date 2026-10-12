package objective

import (
	"context"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestNativeProcessExitRejectsBroadOrMissingEvidence(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
	ctx := auth.WithPrincipal(context.Background(), p)
	for _, mode := range []string{"missing PID", "invalid birth", "extra input", "missing evidence", "valid"} {
		t.Run(mode, func(t *testing.T) {
			inputs := map[string]model.Value{"bundleID": {Kind: model.StringValue, String: "com.fixture.app"}, "processId": {Kind: model.NumberValue, Number: 42}, "processStartToken": {Kind: model.StringValue, String: "1790000000:1"}}
			switch mode {
			case "missing PID":
				delete(inputs, "processId")
			case "invalid birth":
				inputs["processStartToken"] = model.Value{Kind: model.StringValue, String: "wrong"}
			case "extra input":
				inputs["force"] = model.Value{Kind: model.BoolValue, Bool: true}
			}
			calls := 0
			adapter, _ := NewNativeProcessExit(func(context.Context, auth.Principal, model.Surface) (bool, NativeEvidence, error) {
				calls++
				proof := NativeEvidence{HelperEpoch: "read", TargetRef: "process:42:1790000000:1", ObservedAt: time.Now()}
				if mode == "missing evidence" {
					proof.HelperEpoch = ""
				}
				return true, proof, nil
			})
			result, err := adapter.Evaluate(ctx, p, "exited", inputs)
			if mode == "valid" {
				if err != nil || result.Truth != True || calls != 1 {
					t.Fatalf("valid %+v %v", result, err)
				}
			} else if mode == "missing evidence" {
				if err != nil || result.Truth != Unknown {
					t.Fatalf("incomplete %+v %v", result, err)
				}
			} else if err == nil || calls != 0 {
				t.Fatal("malformed exit read reached helper")
			}
		})
	}
}
