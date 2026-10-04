package host

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	repairs "github.com/viant/mechanize/engine/recovery"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

func TestRecoveryGuardReadbackFailureReleasesNativeFence(t *testing.T) {
	h, f := hostControlFixture(t)
	r, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("recovery guard dispatched input")
		return automation.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Runtime = r
	owned, err := r.Open(f.ctx, "recovery guard")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(f.ctx, owned.SessionID) })
	ctx := auth.WithConsentBinding(f.ctx, auth.ConsentBinding{SessionID: owned.SessionID, Purpose: "Read stopped recovery boundary"})
	readError := errors.New("fixture readback unavailable")
	h.recovery, err = repairs.New(repairs.Options{
		Invoke:    func(context.Context, auth.Principal, exec.ComponentRequest) (any, error) { return nil, readError },
		Authorize: func(context.Context, auth.Principal, model.Surface) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	release, err := h.recoveryGuard(ctx, f.principal, repairs.RunReference{RunID: "run", PlanID: "plan", Revision: 3, Status: "paused"})
	if !errors.Is(err, readError) || release != nil {
		t.Fatalf("readback failure lost: release=%v err=%v", release != nil, err)
	}
	if f.starts != 0 || f.calls != 0 {
		t.Fatal("failed recovery guard acquired input helper")
	}
	competitor := competingReconciliationSupervisor(t, f)
	if _, err := competitor.Acquire(f.ctx, f.principal, session.Scope{AllowedBundles: []string{"com.fixture.app"}}); err != nil {
		t.Fatalf("readback failure retained fence: %v", err)
	}
}

func TestRecoveryRuntimeRequiresCurrentOwnedSession(t *testing.T) {
	h, f := hostControlFixture(t)
	r, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("readiness dispatched input")
		return automation.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Runtime = r
	session, err := r.Open(f.ctx, "recovery fixture")
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithConsentBinding(f.ctx, auth.ConsentBinding{SessionID: session.SessionID, Purpose: "Repair a changed locator"})
	if err := h.recoveryRuntimeReady(ctx, f.principal); err != nil {
		t.Fatal(err)
	}
	for _, c := range []context.Context{
		f.ctx,
		auth.WithConsentBinding(f.ctx, auth.ConsentBinding{SessionID: session.SessionID}),
		auth.WithConsentBinding(f.ctx, auth.ConsentBinding{SessionID: "other-session", Purpose: "repair"}),
	} {
		if h.recoveryRuntimeReady(c, f.principal) == nil {
			t.Fatal("missing or foreign binding admitted")
		}
	}
	if err := r.Close(f.ctx, session.SessionID); err != nil {
		t.Fatal(err)
	}
	if h.recoveryRuntimeReady(ctx, f.principal) == nil {
		t.Fatal("closed session marked ready")
	}
	if f.starts != 0 || f.calls != 0 {
		t.Fatal("readiness acquired input helper")
	}
}

func TestNativeRecoveryBoundaryRejectsBroaderOrChangedSnapshot(t *testing.T) {
	ref := repairs.RunReference{RunID: "run", PlanID: "plan", ObjectiveID: "objective", Revision: 3, Status: "paused", ContentHash: "content", PlanHash: "plan-hash", ObjectiveHash: "objective-hash"}
	fixture := func() repairs.Snapshot {
		return repairs.Snapshot{Reference: ref, Plan: model.Plan{Steps: []model.Step{controlStep()}}}
	}
	if err := validateNativeRecoveryBoundary(fixture(), ref); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*repairs.Snapshot)
	}{
		{"unknown", func(s *repairs.Snapshot) { s.Unknown = true }},
		{"revision", func(s *repairs.Snapshot) { s.Reference.Revision++ }},
		{"objective", func(s *repairs.Snapshot) { s.Reference.ObjectiveHash = "changed" }},
		{"running", func(s *repairs.Snapshot) { s.Reference.Status = "running" }},
		{"missing plan", func(s *repairs.Snapshot) { s.Plan.Steps = nil }},
		{"mixed surface", func(s *repairs.Snapshot) {
			web := controlStep()
			web.Target.Surface = model.Surface{Kind: "web", Origin: "https://example.com"}
			s.Plan.Steps = append(s.Plan.Steps, web)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := fixture()
			test.change(&s)
			if validateNativeRecoveryBoundary(s, ref) == nil {
				t.Fatal("unqualified boundary accepted")
			}
		})
	}
}
