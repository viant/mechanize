package commitoutcome

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	integration "github.com/viant/mechanize/integration/endly"
	xhandler "github.com/viant/xdatly/handler"
	"testing"
)

func TestDispatchedOutcomeRequiresUnverifiedReceiptAndCannotPromoteUnknown(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "outcome", nil)
	ctx, e := data.WithScope(context.Background(), data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if e != nil {
		t.Fatal(e)
	}
	ptr := func(v string) *string { return &v }
	revision := 2
	for _, mode := range []string{"valid", "unknownPredecessor", "missingPredecessor", "missingReceipt", "unknownReceipt", "verifiedReceipt", "milestone"} {
		t.Run(mode, func(t *testing.T) {
			row := &Effect{}
			row.SetNamespace(ptr(p.Namespace))
			row.SetRunId(ptr("run"))
			row.SetAttemptId(ptr("attempt"))
			row.SetRevision(&revision)
			row.SetState(ptr("dispatched"))
			row.SetEvents([]*Event{{}})
			receipt := integration.StepResult{DispatchState: "dispatched", VerificationState: "unverified"}
			prior := &Effect{Namespace: ptr(p.Namespace), RunId: ptr("run"), AttemptId: ptr("attempt"), State: ptr("intent")}
			switch mode {
			case "unknownPredecessor":
				prior.State = ptr("unknown")
			case "missingPredecessor":
				prior.State = nil
			case "unknownReceipt":
				receipt.DispatchState = "unknown"
			case "verifiedReceipt":
				receipt.VerificationState = "verified"
			case "milestone":
				row.SetMilestones([]*Milestone{{}})
			}
			raw, _ := json.Marshal(receipt)
			row.SetEvidenceJson(ptr(string(raw)))
			if mode == "missingReceipt" {
				row.EvidenceJson = nil
			}
			state := xhandler.LifecycleContext[Effect, xhandler.NoParent, CommitOutcomeOutput]{}
			state.Previous = prior
			e := EffectLifecycleHooks.Validate(ctx, row, state)
			if (e == nil) != (mode == "valid") {
				t.Fatal("wrong dispatch proof admission", e)
			}
		})
	}
}
