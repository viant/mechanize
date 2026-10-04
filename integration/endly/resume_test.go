package endly

import (
	"context"
	"errors"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"sync/atomic"
	"testing"
	"time"
)

func TestResumeCorrelationGateAndOriginalIndex(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed", true: "rejected"}[fail], func(t *testing.T) {
			ctx := actor(t, "alice")
			p, _ := auth.FromContext(ctx)
			plan, err := script.Compile("app(\"com.example.Fixture\").getById(\"first\").click()\napp(\"com.example.Fixture\").getById(\"second\").click()")
			if err != nil {
				t.Fatal(err)
			}
			var attached, calls atomic.Int32
			r, err := NewWithOptions(func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (StepResult, error) {
				if attached.Load() != 1 {
					return StepResult{}, errors.New("dispatch preceded correlation")
				}
				meta, _ := ExecutionFromContext(ctx)
				if meta.StepIndex != 1 || step.ID != plan.Steps[1].ID {
					return StepResult{}, errors.New("original plan index lost")
				}
				calls.Add(1)
				return StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
			}, Options{LoadResume: func(context.Context, auth.Principal, string, int, string, string) (ResumeSnapshot, error) {
				return ResumeSnapshot{RunID: "run", PlanID: "plan", ObjectiveID: "objective", Status: "running", Revision: 3, Plan: *plan, Completed: map[string]StepResult{plan.Steps[0].ID: {VerificationState: "verified"}}}, nil
			}, AttachOperation: func(context.Context, auth.Principal, string, int, string, string) error {
				if fail {
					return errors.New("commit rejected")
				}
				attached.Store(1)
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			result, err := r.Resume(ctx, p, "run", 3, "plan", "objective")
			if fail {
				if err == nil || calls.Load() != 0 {
					t.Fatalf("rejected resume dispatched: %v %d", err, calls.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wait, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			finished, err := r.Wait(wait, result.SessionID, result.Operation.ID)
			if err != nil || finished.Status != manager.OperationSucceeded || calls.Load() != 1 {
				t.Fatalf("resume: %+v %v calls=%d", finished, err, calls.Load())
			}
		})
	}
}

func TestResumeInOwnedSessionConsentAndFailure(t *testing.T) {
	for _, rejectCommit := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed", true: "rejected"}[rejectCommit], func(t *testing.T) {
			ctx := actor(t, "alice")
			principal, _ := auth.FromContext(ctx)
			principal.ClientID = "client-a"
			ctx = auth.WithPrincipal(ctx, principal)
			plan, err := script.Compile("app(\"com.example.Fixture\").getById(\"first\").click()\napp(\"com.example.Fixture\").getById(\"second\").click()")
			if err != nil {
				t.Fatal(err)
			}
			plan.Steps[1].Effect.BusinessKey = map[string]model.Value{"invoice": {Kind: model.StringValue, String: "invoice-42"}}
			var sessionID string
			var attached, calls, completions atomic.Int32
			r, err := NewWithOptions(func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (StepResult, error) {
				binding, ok := auth.ConsentBindingFromContext(ctx)
				meta, _ := ExecutionFromContext(ctx)
				if !ok || binding.SessionID != sessionID || binding.GrantID != "grant" || attached.Load() != 1 || meta.StepIndex != 1 || meta.RunID != "run" || meta.PlanID != "plan" || step.Effect.BusinessKey["invoice"].String != "invoice-42" {
					return StepResult{}, errors.New("resume lost consent, correlation or original identity")
				}
				calls.Add(1)
				return StepResult{VerificationState: "verified"}, nil
			}, Options{LoadResume: func(context.Context, auth.Principal, string, int, string, string) (ResumeSnapshot, error) {
				return ResumeSnapshot{RunID: "run", PlanID: "plan", ObjectiveID: "objective", Revision: 3, Status: "paused", Plan: *plan, Completed: map[string]StepResult{plan.Steps[0].ID: {VerificationState: "verified"}}}, nil
			}, AttachOperation: func(ctx context.Context, p auth.Principal, run string, revision int, session, operation string) error {
				if session != sessionID || operation == "" {
					return errors.New("wrong correlation")
				}
				if rejectCommit {
					return errors.New("commit rejected")
				}
				attached.Store(1)
				return nil
			}, CompleteObjective: func(context.Context, auth.Principal, CompletionRequest) (BusinessResult, error) {
				completions.Add(1)
				return BusinessResult{BusinessStatus: "unverified", VerificationState: "unverified"}, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			session, err := r.Open(ctx, "owned")
			if err != nil {
				t.Fatal(err)
			}
			sessionID = session.SessionID
			t.Cleanup(func() { _ = r.Close(ctx, sessionID) })
			ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: sessionID, GrantID: "grant", Purpose: "resume"})
			result, err := r.ResumeInSession(ctx, principal, sessionID, "run", 3, "plan", "objective")
			if rejectCommit {
				if err == nil || calls.Load() != 0 {
					t.Fatalf("uncommitted dispatch: %v calls=%d", err, calls.Load())
				}
				if _, err = r.authorize(ctx, sessionID); err != nil {
					t.Fatalf("caller session closed: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.SessionID != sessionID {
				t.Fatal("session changed")
			}
			wait, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			finished, err := r.Wait(wait, sessionID, result.Operation.ID)
			if err != nil || finished.Status != manager.OperationSucceeded || calls.Load() != 1 || completions.Load() != 1 {
				t.Fatalf("resume: %+v %v calls=%d completion=%d", finished, err, calls.Load(), completions.Load())
			}
		})
	}
}

func TestResumeAdmissionRejectsWrongSessionAndClient(t *testing.T) {
	ctx := actor(t, "alice")
	p, _ := auth.FromContext(ctx)
	p.ClientID = "client-a"
	ctx = auth.WithPrincipal(ctx, p)
	var loads atomic.Int32
	r, err := NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		t.Fatal("unexpected dispatch")
		return StepResult{}, nil
	}, Options{LoadResume: func(context.Context, auth.Principal, string, int, string, string) (ResumeSnapshot, error) {
		loads.Add(1)
		return ResumeSnapshot{}, errors.New("unreachable")
	}, AttachOperation: func(context.Context, auth.Principal, string, int, string, string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "owned")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(ctx, session.SessionID) })
	for _, test := range []struct {
		name    string
		ctx     context.Context
		actor   auth.Principal
		session string
	}{
		{"wrong grant session", auth.WithConsentBinding(ctx, auth.ConsentBinding{GrantID: "grant", SessionID: "old-session"}), p, session.SessionID},
		{"grant without session", auth.WithConsentBinding(ctx, auth.ConsentBinding{GrantID: "grant"}), p, session.SessionID},
		{"unknown session", ctx, p, "unknown"},
		{"other user", actor(t, "bob"), p, session.SessionID},
		{"other client", auth.WithPrincipal(ctx, func() auth.Principal { other := p; other.ClientID = "client-b"; return other }()), p, session.SessionID},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := r.ResumeInSession(test.ctx, test.actor, test.session, "run", 3, "plan", "objective"); err == nil {
				t.Fatal("unexpected admission")
			}
		})
	}
	if loads.Load() != 0 {
		t.Fatal("unauthorized request reached loader")
	}
	grantCtx := auth.WithConsentBinding(ctx, auth.ConsentBinding{GrantID: "grant", SessionID: session.SessionID})
	if _, err := r.Resume(grantCtx, p, "run", 3, "plan", "objective"); err == nil {
		t.Fatal("legacy resume moved grant")
	}
	if _, err := r.Resume(ctx, p, "run", 3, "plan", "objective"); err == nil {
		t.Fatal("expected loader failure")
	}
	r.mu.RLock()
	count := len(r.principals)
	r.mu.RUnlock()
	if count != 1 {
		t.Fatalf("internal session leaked: %d", count)
	}
}

func TestResumeSnapshotAndStoppedBoundary(t *testing.T) {
	ctx := actor(t, "alice")
	p, _ := auth.FromContext(ctx)
	plan, err := script.Compile("app(\"com.example.Fixture\").getById(\"first\").click()")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ResumeSnapshot)
	}{
		{"run", func(s *ResumeSnapshot) { s.RunID = "other" }},
		{"revision", func(s *ResumeSnapshot) { s.Revision++ }},
		{"plan", func(s *ResumeSnapshot) { s.PlanID = "other" }},
		{"objective", func(s *ResumeSnapshot) { s.ObjectiveID = "other" }},
		{"terminal", func(s *ResumeSnapshot) { s.Status = "succeeded" }},
		{"unknown milestone", func(s *ResumeSnapshot) {
			s.Completed = map[string]StepResult{"unknown": {VerificationState: "verified"}}
		}},
		{"unverified milestone", func(s *ResumeSnapshot) {
			s.Completed = map[string]StepResult{plan.Steps[0].ID: {VerificationState: "unknown"}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := ResumeSnapshot{RunID: "run", PlanID: "plan", ObjectiveID: "objective", Revision: 3, Status: "paused", Plan: *plan}
			test.mutate(&snapshot)
			r, err := NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
				t.Fatal("unexpected dispatch")
				return StepResult{}, nil
			}, Options{LoadResume: func(context.Context, auth.Principal, string, int, string, string) (ResumeSnapshot, error) {
				return snapshot, nil
			}, AttachOperation: func(context.Context, auth.Principal, string, int, string, string) error {
				t.Fatal("unexpected correlation")
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			session, err := r.Open(ctx, "owned")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close(ctx, session.SessionID) })
			if _, err = r.ResumeInSession(ctx, p, session.SessionID, "run", 3, "plan", "objective"); err == nil {
				t.Fatal("invalid snapshot admitted")
			}
			if _, err = r.authorize(ctx, session.SessionID); err != nil {
				t.Fatal("caller session closed")
			}
		})
	}
	t.Run("running boundary", func(t *testing.T) {
		started := make(chan struct{})
		var loads atomic.Int32
		r, err := NewWithOptions(func(ctx context.Context, _ auth.Principal, _ model.Step, _ map[string]model.Value) (StepResult, error) {
			close(started)
			<-ctx.Done()
			return StepResult{}, ctx.Err()
		}, Options{LoadResume: func(context.Context, auth.Principal, string, int, string, string) (ResumeSnapshot, error) {
			loads.Add(1)
			return ResumeSnapshot{}, errors.New("unexpected loader")
		}, AttachOperation: func(context.Context, auth.Principal, string, int, string, string) error { return nil }})
		if err != nil {
			t.Fatal(err)
		}
		session, err := r.Open(ctx, "owned")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close(ctx, session.SessionID) })
		operation, err := r.StartPlan(context.WithValue(ctx, requestKey{}, "run"), session.SessionID, *plan, nil)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("operation never started")
		}
		if _, err = r.ResumeInSession(ctx, p, session.SessionID, "run", 3, "plan", "objective"); err == nil || loads.Load() != 0 {
			t.Fatal("live operation passed resume admission")
		}
		_, _ = r.Cancel(ctx, session.SessionID, operation.ID)
	})
}

func TestResumeExecutionAuthorityIsInternalAndCorrelationBound(t *testing.T) {
	ctx := actor(t, "internal-resume-authority")
	p, _ := auth.FromContext(ctx)
	plan, err := script.Compile("app(\"com.example.Fixture\").getById(\"first\").click()\napp(\"com.example.Fixture\").getById(\"second\").click()")
	if err != nil {
		t.Fatal(err)
	}
	evilFlag := model.Value{Kind: model.BoolValue, Bool: true}
	evilOperation := model.Value{Kind: model.StringValue, String: "forged-operation"}
	plan.Bindings = append(plan.Bindings, model.Binding{Name: "Resumed", Type: "value", Value: &evilFlag}, model.Binding{Name: "OperationID", Type: "value", Value: &evilOperation})
	seen := make(chan ExecutionMetadata, 3)
	r, err := NewWithOptions(func(c context.Context, _ auth.Principal, _ model.Step, _ map[string]model.Value) (StepResult, error) {
		m, _ := ExecutionFromContext(c)
		seen <- m
		return StepResult{VerificationState: "verified"}, nil
	}, Options{LoadResume: func(_ context.Context, _ auth.Principal, run string, revision int, planID, objectiveID string) (ResumeSnapshot, error) {
		return ResumeSnapshot{RunID: run, Revision: revision, PlanID: planID, ObjectiveID: objectiveID, Status: "paused", Plan: *plan, Values: map[string]model.Value{"Resumed": evilFlag, "OperationID": evilOperation}, Completed: map[string]StepResult{plan.Steps[0].ID: {VerificationState: "verified"}}}, nil
	}, AttachOperation: func(context.Context, auth.Principal, string, int, string, string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "metadata fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.SessionID)
	op, err := r.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = r.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		metadata := <-seen
		if metadata.Resumed || metadata.OperationID != "" {
			t.Fatal("typed values forged resumed operation authority")
		}
	}
	runID, err := r.RunReference(ctx, session.SessionID, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := r.ResumeInSession(ctx, p, session.SessionID, runID, 1, "plan", "objective")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Wait(wait, session.SessionID, resumed.Operation.ID); err != nil {
		t.Fatal(err)
	}
	metadata := <-seen
	if !metadata.Resumed || metadata.OperationID != resumed.Operation.ID || metadata.SessionID != session.SessionID || metadata.RunID != runID || metadata.StepIndex != 1 {
		t.Fatalf("internal resumed correlation lost: %+v", metadata)
	}
}
