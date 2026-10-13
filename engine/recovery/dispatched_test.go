package recovery

import (
	"encoding/json"
	integration "github.com/viant/mechanize/integration/endly"
	"testing"
)

func TestRecoveryPreservesDispatchedPrefixWithoutVerifiedMilestone(t *testing.T) {
	for _, mode := range []string{"valid", "postcondition", "milestone", "unknownReceipt", "oldUnknown"} {
		t.Run(mode, func(t *testing.T) {
			ctx, p, row, opts := recoveryFixture(t)
			var envelope planEnvelope
			if e := json.Unmarshal([]byte(*row.Plans[0].ContentJson), &envelope); e != nil {
				t.Fatal(e)
			}
			if mode != "postcondition" {
				envelope.Plan.Steps[0].Postcondition = nil
			}
			raw, _ := json.Marshal(envelope)
			row.Plans[0].ContentJson = ptr(string(raw))
			row.Plans[0].ContentHash = ptr(digest(raw))
			row.Effects[0].State = ptr("dispatched")
			proof := integration.StepResult{DispatchState: "dispatched", VerificationState: "unverified"}
			if mode == "unknownReceipt" {
				proof.DispatchState = "unknown"
			}
			raw, _ = json.Marshal(proof)
			row.Effects[0].EvidenceJson = ptr(string(raw))
			if mode != "milestone" {
				row.Milestones = nil
			}
			if mode == "oldUnknown" {
				row.Effects[0].State = ptr("unknown")
			}
			opts.Invoke = scopedMemory(row)
			s, e := New(opts)
			if e != nil {
				t.Fatal(e)
			}
			snapshot, e := s.Snapshot(ctx, p, *row.Id)
			if mode == "oldUnknown" {
				if e != nil || !snapshot.Unknown || len(snapshot.Completed) != 0 {
					t.Fatal("old unknown promoted", e)
				}
				return
			}
			if mode != "valid" {
				if e == nil {
					t.Fatal("invalid dispatched proof accepted")
				}
				return
			}
			if e != nil || snapshot.Unknown || snapshot.CompletedSteps != 1 || !snapshot.Completed["save"].DispatchedUnverified() || len(snapshot.Raw.Milestones) != 0 {
				t.Fatal("known dispatch lost or verified milestone invented", e)
			}
		})
	}
}
