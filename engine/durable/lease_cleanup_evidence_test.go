package durable

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data/leasecleanupevidence"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGeneratedLeaseNeverDispatchedCompleteOriginalOutcomes(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture:issuer", "", "physical-cleanup-owner", []string{"desktop:control"})
	ctx := auth.WithPrincipal(context.Background(), p)
	epoch := 22
	calls := 0
	outcome := integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return epoch, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		calls++
		return outcome, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	if proof, err := b.LeaseNeverDispatched(ctx, p, epoch); err == nil || proof.ProofKnown {
		t.Fatal("missing database proved input absence")
	}
	plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"fixtureCase": {Kind: model.StringValue, String: "case-1"}}
	if _, err = b.PreparePlan(ctx, p, "cleanup-prepared", "session", *plan, nil); err != nil {
		t.Fatal(err)
	}
	proof, err := b.LeaseNeverDispatched(ctx, p, epoch)
	if err != nil || !proof.ProofKnown || !proof.NeverDispatched || proof.AttemptCount != 0 {
		t.Fatalf("empty existing proof: %+v %v", proof, err)
	}
	orchestrator, err := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan})
	if err != nil {
		t.Fatal(err)
	}
	run := func() {
		t.Helper()
		session, err := orchestrator.Open(ctx, "physical cleanup fixture")
		if err != nil {
			t.Fatal(err)
		}
		op, err := orchestrator.StartPlan(ctx, session.SessionID, *plan, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = orchestrator.Wait(ctx, session.SessionID, op.ID)
	}
	run()
	run()
	proof, err = b.LeaseNeverDispatched(ctx, p, epoch)
	if err != nil || !proof.ProofKnown || !proof.NeverDispatched || proof.AttemptCount != 2 {
		t.Fatalf("original pre-dispatch outcomes: %+v %v", proof, err)
	}
	use, err := b.LeaseUse(ctx, p, epoch)
	if err != nil || !use.IntentsPresent {
		t.Fatal("new proof weakened existing zero-intent contract")
	}
	epoch = 23
	outcome = integration.StepResult{DispatchState: "unknown", VerificationState: "unknown"}
	run()
	if proof, err = b.LeaseNeverDispatched(ctx, p, epoch); err == nil || proof.ProofKnown {
		t.Fatalf("unknown effect qualified: %+v %v", proof, err)
	}
	epoch = 24
	outcome = integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}
	run()
	if proof, err = b.LeaseNeverDispatched(ctx, p, epoch); err == nil || proof.ProofKnown {
		t.Fatalf("confirmed effect qualified: %+v %v", proof, err)
	}
	proof, err = b.LeaseNeverDispatched(ctx, p, 22)
	if err != nil || proof.AttemptCount != 2 || !proof.NeverDispatched {
		t.Fatalf("unrelated generations contaminated exact proof: %+v %v", proof, err)
	}
	if proof, err = b.LeaseNeverDispatched(ctx, p, 23); err == nil || proof.ProofKnown {
		t.Fatal("exact recovery proof resolved another generation's unknown effects")
	}
	if calls != 4 {
		t.Fatalf("read-only evidence dispatched: %d", calls)
	}
	other, _ := auth.NewPrincipal("fixture:issuer", "", "other", nil)
	if proof, err = b.LeaseNeverDispatched(ctx, other, 22); !errors.Is(err, auth.ErrUnauthorized) || proof.ProofKnown {
		t.Fatal("foreign owner proof accepted")
	}
}

func safeAttemptEvidence() *leasecleanupevidence.AttemptEvidence {
	id := "attempt"
	payload := `{"dispatchState":"notDispatched","verificationState":"unknown"}`
	return &leasecleanupevidence.AttemptEvidence{Namespace: pointer("owner"), Id: &id, RunId: pointer("run"), LeaseEpoch: pointer(22), TotalAttempts: 1, EffectId: pointer(key("effect", id)), EffectState: pointer("absent"), EffectRevision: pointer(2), EvidenceJson: &payload, IntentEventId: pointer(key("intent-event", id)), IntentSequence: pointer(3), OutcomeEventId: pointer(key("outcome-event", id)), OutcomeSequence: pointer(4), OutcomePayloadJson: &payload}
}
func TestNeverDispatchedRejectsIncompleteOrLaterReconciliationEvidence(t *testing.T) {
	cases := []struct {
		name   string
		change func(*leasecleanupevidence.AttemptEvidence)
	}{
		{"missing effect", func(r *leasecleanupevidence.AttemptEvidence) { r.EffectId = nil }},
		{"unknown effect", func(r *leasecleanupevidence.AttemptEvidence) { r.EffectState = pointer("unknown") }},
		{"confirmed effect", func(r *leasecleanupevidence.AttemptEvidence) { r.EffectState = pointer("confirmed") }},
		{"later absence reconciliation", func(r *leasecleanupevidence.AttemptEvidence) { r.EffectRevision = pointer(3) }},
		{"original event missing", func(r *leasecleanupevidence.AttemptEvidence) { r.OutcomeEventId = nil }},
		{"reconciliation event substituted", func(r *leasecleanupevidence.AttemptEvidence) { r.OutcomeEventId = pointer("reconciled") }},
		{"event payload differs", func(r *leasecleanupevidence.AttemptEvidence) {
			r.OutcomePayloadJson = pointer(`{"dispatchState":"unknown"}`)
		}},
		{"dispatched evidence", func(r *leasecleanupevidence.AttemptEvidence) {
			r.EvidenceJson = pointer(`{"dispatchState":"dispatched"}`)
			r.OutcomePayloadJson = r.EvidenceJson
		}},
		{"truncated projection", func(r *leasecleanupevidence.AttemptEvidence) { r.TotalAttempts = 2 }},
		{"nonoriginal sequence", func(r *leasecleanupevidence.AttemptEvidence) { r.OutcomeSequence = pointer(5) }},
		{"invalid json", func(r *leasecleanupevidence.AttemptEvidence) {
			r.EvidenceJson = pointer("invalid")
			r.OutcomePayloadJson = r.EvidenceJson
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := safeAttemptEvidence()
			tc.change(row)
			if _, err := validateNeverDispatched([]*leasecleanupevidence.AttemptEvidence{row}, "owner", 22); err == nil {
				t.Fatal("unsafe input absence proof accepted")
			}
		})
	}
	if _, err := validateNeverDispatched([]*leasecleanupevidence.AttemptEvidence{safeAttemptEvidence()}, "owner", 22); err != nil {
		t.Fatal(err)
	}
	first := safeAttemptEvidence()
	first.TotalAttempts = 2
	if _, err := validateNeverDispatched([]*leasecleanupevidence.AttemptEvidence{first, first}, "owner", 22); err == nil {
		t.Fatal("duplicate attempts hid a missing attempt")
	}
}
